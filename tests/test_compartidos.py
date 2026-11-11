import hashlib
import re

import pytest

from boveda import db as base_datos
from boveda.criptografia import simetrico
from boveda.servicios import compartidos, mensajes, usuarios
from boveda.servicios.comun import NoEncontrado

CONTRASENA = "contraseña-segura-1"


@pytest.fixture
def ana(db):
    return usuarios.registrar(db, "ana", CONTRASENA)


@pytest.fixture
def beto(db):
    return usuarios.registrar(db, "beto", CONTRASENA)


def _enviar(db, clave, remitente, asunto="Clave", cuerpo="La clave es 4321", destinatario="beto"):
    return mensajes.enviar(db, clave, remitente, destinatario, asunto, cuerpo, CONTRASENA)


def _token(cliente):
    cliente.get("/login")
    with cliente.session_transaction() as sesion:
        return sesion["csrf"]


def _registrar(cliente, nombre):
    return cliente.post(
        "/registro",
        data={"nombre": nombre, "contrasena": CONTRASENA, "confirmacion": CONTRASENA, "csrf_token": _token(cliente)},
    )


def _enviar_web(cliente, destinatario, asunto, cuerpo):
    return cliente.post(
        "/mensajes/nuevo",
        data={
            "destinatario": destinatario,
            "asunto": asunto,
            "cuerpo": cuerpo,
            "contrasena": CONTRASENA,
            "csrf_token": _token(cliente),
        },
    )


def _id_desde_redireccion(respuesta):
    return respuesta.headers["Location"].rstrip("/").split("/")[-1]


def _enlace_web(cliente, mensaje_id):
    return cliente.post(
        f"/mensajes/{mensaje_id}/compartir",
        data={"csrf_token": _token(cliente)},
        follow_redirects=True,
    )


def _token_del_html(html):
    return re.search(r"/p/([A-Za-z0-9_-]+)", html).group(1)


def _consulta(app, sql, *params):
    conexion = base_datos.conectar(app.config["RUTA_BD"])
    try:
        return [dict(fila) for fila in conexion.execute(sql, params).fetchall()]
    finally:
        conexion.close()


def test_el_token_se_guarda_solo_como_hash(db, clave_datos, ana, beto):
    mensaje_id = _enviar(db, clave_datos, ana)
    enlace = compartidos.crear_enlace(db, mensaje_id, ana)
    fila = db.execute("SELECT token_hash FROM compartidos WHERE id = ?", (enlace.id,)).fetchone()
    assert fila["token_hash"] == hashlib.sha256(enlace.token.encode("utf-8")).hexdigest()
    assert enlace.token not in str(dict(fila))
    assert len(enlace.token) >= 40


def test_el_enlace_publico_lee_el_mensaje(db, clave_datos, ana, beto):
    mensaje_id = _enviar(db, clave_datos, ana, asunto="Clave de la sala", cuerpo="La clave es 4321")
    enlace = compartidos.crear_enlace(db, mensaje_id, ana)
    publico = compartidos.resolver_enlace(db, clave_datos, enlace.token)
    assert publico.mensaje.asunto == "Clave de la sala"
    assert publico.mensaje.cuerpo == "La clave es 4321"
    assert publico.mensaje.estado_firma == mensajes.VALIDA
    assert publico.creado_por == "ana"


def test_token_invalido_no_abre_nada(db, clave_datos, ana, beto):
    with pytest.raises(NoEncontrado):
        compartidos.resolver_enlace(db, clave_datos, "token-que-no-existe")
    assert "token_hash" not in str(compartidos.listar_enlaces(db, _enviar(db, clave_datos, ana), ana))


def test_enlace_caducado_no_abre_nada(db, clave_datos, ana, beto):
    mensaje_id = _enviar(db, clave_datos, ana)
    enlace = compartidos.crear_enlace(db, mensaje_id, ana)
    db.execute("UPDATE compartidos SET expira_en = ? WHERE id = ?", ("2000-01-01T00:00:00+00:00", enlace.id))
    db.commit()
    with pytest.raises(NoEncontrado):
        compartidos.resolver_enlace(db, clave_datos, enlace.token)


def test_revocar_el_enlace_lo_invalida(db, clave_datos, ana, beto):
    mensaje_id = _enviar(db, clave_datos, ana)
    enlace = compartidos.crear_enlace(db, mensaje_id, ana)
    compartidos.revocar_enlace(db, mensaje_id, enlace.id, ana)
    with pytest.raises(NoEncontrado):
        compartidos.resolver_enlace(db, clave_datos, enlace.token)
    assert compartidos.listar_enlaces(db, mensaje_id, ana)[0]["activo"] is False


def test_solo_los_participantes_crean_o_revocan_enlaces(db, clave_datos, ana, beto):
    carla = usuarios.registrar(db, "carla", CONTRASENA)
    mensaje_id = _enviar(db, clave_datos, ana)
    with pytest.raises(NoEncontrado):
        compartidos.crear_enlace(db, mensaje_id, carla)
    enlace = compartidos.crear_enlace(db, mensaje_id, ana)
    with pytest.raises(NoEncontrado):
        compartidos.revocar_enlace(db, mensaje_id, enlace.id, carla)


def test_eliminar_el_mensaje_borra_sus_enlaces(db, clave_datos, ana, beto):
    mensaje_id = _enviar(db, clave_datos, ana)
    enlace = compartidos.crear_enlace(db, mensaje_id, ana)
    mensajes.eliminar(db, ana, mensaje_id)
    assert db.execute("SELECT COUNT(*) FROM compartidos").fetchone()[0] == 0
    with pytest.raises(NoEncontrado):
        compartidos.resolver_enlace(db, clave_datos, enlace.token)


def test_el_enlace_muestra_la_alteracion_con_la_clave_maestra(db, clave_datos, ana, beto):
    mensaje_id = _enviar(db, clave_datos, ana, asunto="Pago", cuerpo="Monto: 100")
    enlace = compartidos.crear_enlace(db, mensaje_id, ana)
    fila = db.execute("SELECT remitente_id, destinatario_id FROM mensajes WHERE id = ?", (mensaje_id,)).fetchone()
    contexto = mensajes.contexto_mensaje(fila["remitente_id"], fila["destinatario_id"], mensaje_id, "cuerpo")
    db.execute(
        "UPDATE mensajes SET cuerpo_cifrado = ? WHERE id = ?",
        (simetrico.cifrar_texto("Monto: 900", clave_datos, contexto), mensaje_id),
    )
    db.commit()
    publico = compartidos.resolver_enlace(db, clave_datos, enlace.token)
    assert publico.mensaje.descifrable
    assert publico.mensaje.cuerpo == "Monto: 900"
    assert publico.mensaje.estado_firma == mensajes.INVALIDA


def test_listar_enlaces_no_expone_el_token_ni_el_hash(db, clave_datos, ana, beto):
    mensaje_id = _enviar(db, clave_datos, ana)
    compartidos.crear_enlace(db, mensaje_id, ana)
    enlace = compartidos.listar_enlaces(db, mensaje_id, ana)[0]
    assert set(enlace) == {"id", "creado_en", "expira_en", "revocado_en", "activo"}


def test_crear_enlace_y_abrirlo_sin_cuenta(app, cliente):
    otro = app.test_client()
    _registrar(otro, "beto")
    _registrar(cliente, "ana")
    mensaje_id = _id_desde_redireccion(_enviar_web(cliente, "beto", "Clave de la reunión", "La clave es 4321."))

    respuesta = _enlace_web(cliente, mensaje_id)
    html = respuesta.get_data(as_text=True)
    assert "Enlace creado" in html
    token = _token_del_html(html)

    anonimo = app.test_client()
    publico = anonimo.get(f"/p/{token}")
    pagina = publico.get_data(as_text=True)
    assert publico.status_code == 200
    assert "Clave de la reunión" in pagina
    assert "La clave es 4321." in pagina
    assert "Firmado" in pagina
    assert "solo lectura" in pagina
    assert publico.headers["Referrer-Policy"] == "no-referrer"
    assert "noindex" in publico.headers["X-Robots-Tag"]
    assert publico.headers["Cache-Control"] == "no-store"

    assert anonimo.get("/p/token-invalido").status_code == 404
    assert anonimo.get(f"/mensajes/{mensaje_id}").status_code == 302


def test_el_enlace_se_muestra_una_sola_vez(app, cliente):
    otro = app.test_client()
    _registrar(otro, "beto")
    _registrar(cliente, "ana")
    mensaje_id = _id_desde_redireccion(_enviar_web(cliente, "beto", "Asunto", "Texto"))
    html = _enlace_web(cliente, mensaje_id).get_data(as_text=True)
    assert "/p/" in html
    segunda = cliente.get(f"/mensajes/{mensaje_id}").get_data(as_text=True)
    assert "/p/" not in segunda


def test_revocar_el_enlace_lo_cierra(app, cliente):
    otro = app.test_client()
    _registrar(otro, "beto")
    _registrar(cliente, "ana")
    mensaje_id = _id_desde_redireccion(_enviar_web(cliente, "beto", "Asunto", "Texto"))
    html = _enlace_web(cliente, mensaje_id).get_data(as_text=True)
    token = _token_del_html(html)
    enlace_id = re.search(r"/compartir/([0-9a-f]{32})/revocar", html).group(1)

    respuesta = cliente.post(
        f"/mensajes/{mensaje_id}/compartir/{enlace_id}/revocar",
        data={"csrf_token": _token(cliente)},
        follow_redirects=True,
    )
    assert "Enlace revocado" in respuesta.get_data(as_text=True)
    assert app.test_client().get(f"/p/{token}").status_code == 404


def test_un_tercero_no_puede_crear_un_enlace(app, cliente):
    otro = app.test_client()
    _registrar(otro, "beto")
    _registrar(cliente, "ana")
    mensaje_id = _id_desde_redireccion(_enviar_web(cliente, "beto", "Asunto", "Texto"))

    carla = app.test_client()
    _registrar(carla, "carla")
    respuesta = carla.post(f"/mensajes/{mensaje_id}/compartir", data={"csrf_token": _token(carla)})
    assert respuesta.status_code == 404


def test_alterar_el_mensaje_se_ve_en_el_enlace_publico(app, cliente):
    otro = app.test_client()
    _registrar(otro, "beto")
    _registrar(cliente, "ana")
    mensaje_id = _id_desde_redireccion(_enviar_web(cliente, "beto", "Pago", "Monto: 100"))
    token = _token_del_html(_enlace_web(cliente, mensaje_id).get_data(as_text=True))

    fila = _consulta(app, "SELECT remitente_id, destinatario_id FROM mensajes WHERE id = ?", mensaje_id)[0]
    contexto = mensajes.contexto_mensaje(fila["remitente_id"], fila["destinatario_id"], mensaje_id, "cuerpo")
    conexion = base_datos.conectar(app.config["RUTA_BD"])
    conexion.execute(
        "UPDATE mensajes SET cuerpo_cifrado = ? WHERE id = ?",
        (simetrico.cifrar_texto("Monto: 900", app.config["CLAVE_DATOS"], contexto), mensaje_id),
    )
    conexion.commit()
    conexion.close()

    pagina = app.test_client().get(f"/p/{token}").get_data(as_text=True)
    assert "Alterado" in pagina
    assert "Monto: 900" in pagina
    assert "cambió después de firmarse" in pagina


def test_eliminar_el_mensaje_cierra_el_enlace(app, cliente):
    otro = app.test_client()
    _registrar(otro, "beto")
    _registrar(cliente, "ana")
    mensaje_id = _id_desde_redireccion(_enviar_web(cliente, "beto", "Asunto", "Texto"))
    token = _token_del_html(_enlace_web(cliente, mensaje_id).get_data(as_text=True))

    cliente.post(
        f"/mensajes/{mensaje_id}/eliminar",
        data={"csrf_token": _token(cliente)},
        follow_redirects=True,
    )
    assert app.test_client().get(f"/p/{token}").status_code == 404
