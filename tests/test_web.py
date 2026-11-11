import io
import json

from boveda import db as base_datos
from boveda.criptografia import simetrico
from boveda.servicios import mensajes as servicio

CONTRASENA = "contraseña-segura-1"


def _token(cliente):
    cliente.get("/login")
    with cliente.session_transaction() as sesion:
        return sesion["csrf"]


def _registrar(cliente, nombre, contrasena=CONTRASENA):
    return cliente.post(
        "/registro",
        data={"nombre": nombre, "contrasena": contrasena, "confirmacion": contrasena, "csrf_token": _token(cliente)},
    )


def _entrar(cliente, nombre, contrasena=CONTRASENA):
    return cliente.post("/login", data={"nombre": nombre, "contrasena": contrasena, "csrf_token": _token(cliente)})


def _enviar(cliente, destinatario, asunto, cuerpo, contrasena=CONTRASENA):
    return cliente.post(
        "/mensajes/nuevo",
        data={
            "destinatario": destinatario,
            "asunto": asunto,
            "cuerpo": cuerpo,
            "contrasena": contrasena,
            "csrf_token": _token(cliente),
        },
    )


def _id_desde_redireccion(respuesta):
    return respuesta.headers["Location"].rstrip("/").split("/")[-1]


def _consulta(app, sql, *params):
    conexion = base_datos.conectar(app.config["RUTA_BD"])
    try:
        return [dict(fila) for fila in conexion.execute(sql, params).fetchall()]
    finally:
        conexion.close()


def test_rutas_protegidas_redirigen_al_login(cliente):
    respuesta = cliente.get("/mensajes")
    assert respuesta.status_code == 302
    assert "/login" in respuesta.headers["Location"]


def test_flujo_completo_enviar_leer_y_verificar(app, cliente):
    otro = app.test_client()
    assert _registrar(otro, "beto").status_code == 302
    assert _registrar(cliente, "ana").status_code == 302

    respuesta = _enviar(cliente, "beto", "Clave de la reunión", "La clave de la sala es 4321.")
    assert respuesta.status_code == 302
    mensaje_id = _id_desde_redireccion(respuesta)

    fila = _consulta(app, "SELECT asunto_cifrado, cuerpo_cifrado FROM mensajes WHERE id = ?", mensaje_id)[0]
    assert "reunión" not in fila["asunto_cifrado"]
    assert "4321" not in fila["cuerpo_cifrado"]
    assert fila["cuerpo_cifrado"].startswith("v1:")

    html = cliente.get(f"/mensajes/{mensaje_id}").get_data(as_text=True)
    assert "La clave de la sala es 4321." in html
    assert "Firmado" in html
    assert "De ana para beto" in html

    recibidos = otro.get("/mensajes").get_data(as_text=True)
    assert "Clave de la reunión" in recibidos
    assert "De ana" in recibidos
    assert "Firmado" in recibidos

    enviados = cliente.get("/mensajes?bandeja=enviados").get_data(as_text=True)
    assert "Clave de la reunión" in enviados
    assert "Para beto" in enviados

    comprobante = otro.get(f"/mensajes/{mensaje_id}/comprobante")
    assert comprobante.status_code == 200
    assert comprobante.mimetype == "application/json"
    assert "attachment" in comprobante.headers["Content-Disposition"]
    datos = comprobante.get_json()

    anonimo = app.test_client()
    verificacion = anonimo.post(
        "/verificar",
        data={
            "comprobante": (io.BytesIO(json.dumps(datos).encode("utf-8")), "comprobante.json"),
            "csrf_token": _token(anonimo),
        },
        content_type="multipart/form-data",
    )
    assert "Auténtico" in verificacion.get_data(as_text=True)
    assert "El mensaje no cambió después de firmarse" in verificacion.get_data(as_text=True)


def test_enviar_con_contrasena_incorrecta_no_crea_el_mensaje(app, cliente):
    otro = app.test_client()
    _registrar(otro, "beto")
    _registrar(cliente, "ana")
    respuesta = _enviar(cliente, "beto", "No debe guardarse", "Texto", contrasena="contraseña-equivocada")
    assert respuesta.status_code == 400
    assert "Contraseña incorrecta" in respuesta.get_data(as_text=True)
    assert _consulta(app, "SELECT COUNT(*) AS total FROM mensajes")[0]["total"] == 0


def test_un_tercero_no_puede_abrir_el_mensaje(app, cliente):
    beto = app.test_client()
    _registrar(beto, "beto")
    _registrar(cliente, "ana")
    mensaje_id = _id_desde_redireccion(_enviar(cliente, "beto", "Privado", "Solo para Beto"))

    carla = app.test_client()
    _registrar(carla, "carla")
    assert carla.get(f"/mensajes/{mensaje_id}").status_code == 404
    assert carla.post(f"/mensajes/{mensaje_id}/eliminar", data={"csrf_token": _token(carla)}).status_code == 404


def test_alteracion_en_la_base_de_datos_se_muestra_como_alterada(app, cliente):
    beto = app.test_client()
    _registrar(beto, "beto")
    _registrar(cliente, "ana")
    mensaje_id = _id_desde_redireccion(_enviar(cliente, "beto", "Pago", "Monto: 100"))

    fila = _consulta(app, "SELECT remitente_id, destinatario_id FROM mensajes WHERE id = ?", mensaje_id)[0]
    contexto = servicio.contexto_mensaje(fila["remitente_id"], fila["destinatario_id"], mensaje_id, "cuerpo")
    conexion = base_datos.conectar(app.config["RUTA_BD"])
    conexion.execute(
        "UPDATE mensajes SET cuerpo_cifrado = ? WHERE id = ?",
        (simetrico.cifrar_texto("Monto: 900", app.config["CLAVE_DATOS"], contexto), mensaje_id),
    )
    conexion.commit()
    conexion.close()

    html = beto.get(f"/mensajes/{mensaje_id}").get_data(as_text=True)
    assert "Alterado" in html
    assert "no coinciden con la firma" in html


def test_comprobante_de_mensaje_alterado_no_se_descarga(app, cliente):
    beto = app.test_client()
    _registrar(beto, "beto")
    _registrar(cliente, "ana")
    mensaje_id = _id_desde_redireccion(_enviar(cliente, "beto", "Pago", "Monto: 100"))

    fila = _consulta(app, "SELECT remitente_id, destinatario_id FROM mensajes WHERE id = ?", mensaje_id)[0]
    contexto = servicio.contexto_mensaje(fila["remitente_id"], fila["destinatario_id"], mensaje_id, "cuerpo")
    conexion = base_datos.conectar(app.config["RUTA_BD"])
    conexion.execute(
        "UPDATE mensajes SET cuerpo_cifrado = ? WHERE id = ?",
        (simetrico.cifrar_texto("Monto: 900", app.config["CLAVE_DATOS"], contexto), mensaje_id),
    )
    conexion.commit()
    conexion.close()

    respuesta = beto.get(f"/mensajes/{mensaje_id}/comprobante", follow_redirects=True)
    assert "No se emite comprobante" in respuesta.get_data(as_text=True)


def test_verificar_un_comprobante_alterado_falla(app, cliente):
    beto = app.test_client()
    _registrar(beto, "beto")
    _registrar(cliente, "ana")
    mensaje_id = _id_desde_redireccion(_enviar(cliente, "beto", "Factura", "Total: 500"))
    datos = beto.get(f"/mensajes/{mensaje_id}/comprobante").get_json()
    datos["payload"]["cuerpo"] = "Total: 5"

    anonimo = app.test_client()
    verificacion = anonimo.post(
        "/verificar",
        data={
            "comprobante": (io.BytesIO(json.dumps(datos).encode("utf-8")), "comprobante.json"),
            "csrf_token": _token(anonimo),
        },
        content_type="multipart/form-data",
    )
    assert "No se pudo confirmar" in verificacion.get_data(as_text=True)


def test_el_formulario_sin_otros_usuarios_avisa(cliente):
    _registrar(cliente, "ana")
    html = cliente.get("/mensajes/nuevo").get_data(as_text=True)
    assert "necesitas otra cuenta registrada" in html
    assert "<select" not in html


def test_login_incorrecto_no_inicia_sesion(cliente):
    _registrar(cliente, "ana")
    cliente.post("/salir", data={"csrf_token": _token(cliente)})
    respuesta = _entrar(cliente, "ana", contrasena="contraseña-incorrecta")
    assert respuesta.status_code == 401
    assert "Usuario o contraseña incorrectos" in respuesta.get_data(as_text=True)


def test_registro_con_contrasena_corta_se_rechaza(cliente):
    respuesta = _registrar(cliente, "ana", contrasena="corta")
    assert respuesta.status_code == 400
    assert "entre 10 y 128 caracteres" in respuesta.get_data(as_text=True)


def test_post_sin_token_csrf_es_rechazado(cliente):
    _token(cliente)
    respuesta = cliente.post("/salir")
    assert respuesta.status_code == 400


def test_cabeceras_de_seguridad_en_cada_respuesta(cliente):
    respuesta = cliente.get("/login")
    assert "default-src 'self'" in respuesta.headers["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in respuesta.headers["Content-Security-Policy"]
    assert respuesta.headers["X-Frame-Options"] == "DENY"
    assert respuesta.headers["X-Content-Type-Options"] == "nosniff"
    assert respuesta.headers["Cache-Control"] == "no-store"
