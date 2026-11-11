import base64
import io
import json

from boveda import db as base_datos
from boveda.criptografia import simetrico
from boveda.servicios import documentos

CONTRASENA = "contraseña-segura-1"


def _token(cliente):
    cliente.get("/login")
    with cliente.session_transaction() as sesion:
        return sesion["csrf"]


def _registrar(cliente, nombre="ana", contrasena=CONTRASENA):
    return cliente.post(
        "/registro",
        data={"nombre": nombre, "contrasena": contrasena, "confirmacion": contrasena, "csrf_token": _token(cliente)},
    )


def _entrar(cliente, nombre="ana", contrasena=CONTRASENA):
    return cliente.post("/login", data={"nombre": nombre, "contrasena": contrasena, "csrf_token": _token(cliente)})


def _crear(cliente, titulo, contenido):
    return cliente.post(
        "/documentos/nuevo",
        data={"titulo": titulo, "contenido": contenido, "csrf_token": _token(cliente)},
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
    respuesta = cliente.get("/documentos")
    assert respuesta.status_code == 302
    assert "/login" in respuesta.headers["Location"]


def test_flujo_completo_crear_firmar_y_verificar(cliente, app):
    assert _registrar(cliente).status_code == 302

    respuesta = _crear(cliente, "Contrato de renta", "Depósito: 8,000 pesos.\nFecha límite: 30 de noviembre.")
    assert respuesta.status_code == 302
    doc_id = _id_desde_redireccion(respuesta)

    fila = _consulta(app, "SELECT titulo_cifrado, contenido_cifrado FROM documentos WHERE id = ?", doc_id)[0]
    assert "Depósito" not in fila["contenido_cifrado"]
    assert fila["contenido_cifrado"].startswith("v1:")

    html = cliente.get(f"/documentos/{doc_id}").get_data(as_text=True)
    assert "Depósito: 8,000 pesos." in html
    assert "Sin firmar" in html

    erronea = cliente.post(
        f"/documentos/{doc_id}/firmar",
        data={"contrasena": "otra-contrasena", "csrf_token": _token(cliente)},
        follow_redirects=True,
    )
    assert "Contraseña incorrecta" in erronea.get_data(as_text=True)

    firmado = cliente.post(
        f"/documentos/{doc_id}/firmar",
        data={"contrasena": CONTRASENA, "csrf_token": _token(cliente)},
        follow_redirects=True,
    )
    assert "Documento firmado" in firmado.get_data(as_text=True)

    cert = cliente.get(f"/documentos/{doc_id}/certificado")
    assert cert.status_code == 200
    assert cert.mimetype == "application/json"
    assert "attachment" in cert.headers["Content-Disposition"]
    certificado = cert.get_json()

    verificacion = cliente.post(
        "/verificar",
        data={
            "certificado": (io.BytesIO(json.dumps(certificado).encode("utf-8")), "certificado.json"),
            "csrf_token": _token(cliente),
        },
        content_type="multipart/form-data",
    )
    html = verificacion.get_data(as_text=True)
    assert "Auténtico" in html
    assert "El documento no cambió después de firmarse" in html


def test_editar_el_texto_quita_la_firma_en_la_interfaz(cliente):
    _registrar(cliente)
    doc_id = _id_desde_redireccion(_crear(cliente, "Acta", "Acuerdo original"))
    cliente.post(f"/documentos/{doc_id}/firmar", data={"contrasena": CONTRASENA, "csrf_token": _token(cliente)})
    cliente.post(
        f"/documentos/{doc_id}/editar",
        data={"titulo": "Acta", "contenido": "Acuerdo modificado", "csrf_token": _token(cliente)},
    )
    html = cliente.get(f"/documentos/{doc_id}").get_data(as_text=True)
    assert "Sin firmar" in html
    assert "Acuerdo modificado" in html


def test_alteracion_en_la_base_de_datos_se_muestra_como_alterado(cliente, app):
    _registrar(cliente)
    doc_id = _id_desde_redireccion(_crear(cliente, "Pago", "Monto: 100"))
    cliente.post(f"/documentos/{doc_id}/firmar", data={"contrasena": CONTRASENA, "csrf_token": _token(cliente)})

    usuario_id = _consulta(app, "SELECT usuario_id FROM documentos WHERE id = ?", doc_id)[0]["usuario_id"]
    clave = app.config["CLAVE_DATOS"]
    contexto = documentos.contexto_documento(usuario_id, doc_id, "contenido")
    conexion = base_datos.conectar(app.config["RUTA_BD"])
    conexion.execute(
        "UPDATE documentos SET contenido_cifrado = ? WHERE id = ?",
        (simetrico.cifrar_texto("Monto: 900", clave, contexto), doc_id),
    )
    conexion.commit()
    conexion.close()

    html = cliente.get(f"/documentos/{doc_id}").get_data(as_text=True)
    assert "Alterado" in html
    assert "fue alterado" in html


def test_certificado_de_documento_sin_firma_redirige_con_aviso(cliente):
    _registrar(cliente)
    doc_id = _id_desde_redireccion(_crear(cliente, "Borrador", "Aún sin firmar"))
    respuesta = cliente.get(f"/documentos/{doc_id}/certificado", follow_redirects=True)
    assert "Firma el documento antes" in respuesta.get_data(as_text=True)


def test_documento_de_otro_usuario_responde_404(cliente):
    _registrar(cliente, nombre="ana")
    doc_id = _id_desde_redireccion(_crear(cliente, "Privado", "Solo para Ana"))
    cliente.post("/salir", data={"csrf_token": _token(cliente)})
    _registrar(cliente, nombre="beto")
    assert cliente.get(f"/documentos/{doc_id}").status_code == 404


def test_login_incorrecto_no_inicia_sesion(cliente):
    _registrar(cliente)
    cliente.post("/salir", data={"csrf_token": _token(cliente)})
    respuesta = _entrar(cliente, contrasena="contraseña-incorrecta")
    assert respuesta.status_code == 401
    assert "Usuario o contraseña incorrectos" in respuesta.get_data(as_text=True)


def test_registro_con_contrasena_corta_se_rechaza(cliente):
    respuesta = _registrar(cliente, contrasena="corta")
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


def test_verificar_un_certificado_alterado_falla(cliente):
    _registrar(cliente)
    doc_id = _id_desde_redireccion(_crear(cliente, "Factura", "Total: 500"))
    cliente.post(f"/documentos/{doc_id}/firmar", data={"contrasena": CONTRASENA, "csrf_token": _token(cliente)})
    certificado = cliente.get(f"/documentos/{doc_id}/certificado").get_json()
    certificado["payload"]["contenido"] = "Total: 5"

    verificacion = cliente.post(
        "/verificar",
        data={
            "certificado": (io.BytesIO(json.dumps(certificado).encode("utf-8")), "certificado.json"),
            "csrf_token": _token(cliente),
        },
        content_type="multipart/form-data",
    )
    assert "No se pudo confirmar" in verificacion.get_data(as_text=True)


def test_la_clave_publica_del_certificado_viaja_en_base64_valido(cliente):
    _registrar(cliente)
    doc_id = _id_desde_redireccion(_crear(cliente, "Nota", "Texto"))
    cliente.post(f"/documentos/{doc_id}/firmar", data={"contrasena": CONTRASENA, "csrf_token": _token(cliente)})
    certificado = cliente.get(f"/documentos/{doc_id}/certificado").get_json()
    assert len(base64.b64decode(certificado["firma"], validate=True)) == 64
