import base64
import json

import pytest

from boveda.criptografia import asimetrico, simetrico
from boveda.servicios import comprobantes, mensajes, usuarios
from boveda.servicios.comun import ContrasenaIncorrecta, ErrorServicio, NoEncontrado

CONTRASENA = "contraseña-segura-1"


@pytest.fixture
def ana(db):
    return usuarios.registrar(db, "ana", CONTRASENA)


@pytest.fixture
def beto(db):
    return usuarios.registrar(db, "beto", CONTRASENA)


def _enviar(db, clave, remitente, destinatario="beto", asunto="Clave", cuerpo="La clave es 4321", contrasena=CONTRASENA):
    return mensajes.enviar(db, clave, remitente, destinatario, asunto, cuerpo, contrasena)


def _fila(db, mensaje_id):
    return db.execute("SELECT * FROM mensajes WHERE id = ?", (mensaje_id,)).fetchone()


def test_registro_guarda_solo_hash_y_llave_privada_cifrada(db):
    usuario_id = usuarios.registrar(db, "ana.lopez", CONTRASENA)
    fila = usuarios.buscar_por_id(db, usuario_id)
    assert CONTRASENA not in str(dict(fila))
    assert fila["hash_contrasena"].startswith("scrypt$")
    assert fila["clave_privada_cifrada"].startswith("v1:")
    assert fila["clave_publica_pem"].startswith("-----BEGIN PUBLIC KEY-----")


def test_el_nombre_se_normaliza_y_no_se_repite(db, ana):
    with pytest.raises(ErrorServicio, match="ya está en uso"):
        usuarios.registrar(db, "ANA", CONTRASENA)
    assert usuarios.autenticar(db, "ana", CONTRASENA) is not None


def test_autenticacion_rechaza_contrasenas_incorrectas(db, ana):
    assert usuarios.autenticar(db, "ana", "contraseña-equivocada") is None
    assert usuarios.autenticar(db, "nadie", CONTRASENA) is None


def test_el_mensaje_se_guarda_cifrado_y_se_lee_en_claro(db, clave_datos, ana, beto):
    mensaje_id = _enviar(db, clave_datos, ana, asunto="Clave de la sala", cuerpo="La clave es 4321")
    bruto = _fila(db, mensaje_id)
    assert "sala" not in bruto["asunto_cifrado"]
    assert "4321" not in bruto["cuerpo_cifrado"]
    assert bruto["cuerpo_cifrado"].startswith("v1:")

    msg = mensajes.obtener(db, clave_datos, beto, mensaje_id)
    assert (msg.asunto, msg.cuerpo) == ("Clave de la sala", "La clave es 4321")
    assert (msg.remitente, msg.destinatario) == ("ana", "beto")
    assert msg.estado_firma == mensajes.VALIDA
    assert mensajes.obtener(db, clave_datos, ana, mensaje_id).cuerpo == "La clave es 4321"


def test_firmar_exige_la_contrasena_correcta_y_no_guarda_nada(db, clave_datos, ana, beto):
    with pytest.raises(ContrasenaIncorrecta):
        _enviar(db, clave_datos, ana, contrasena="otra-contrasena-123")
    assert db.execute("SELECT COUNT(*) FROM mensajes").fetchone()[0] == 0


def test_un_tercero_no_puede_abrir_ni_eliminar_el_mensaje(db, clave_datos, ana, beto):
    carla = usuarios.registrar(db, "carla", CONTRASENA)
    mensaje_id = _enviar(db, clave_datos, ana)
    with pytest.raises(NoEncontrado):
        mensajes.obtener(db, clave_datos, carla, mensaje_id)
    with pytest.raises(NoEncontrado):
        mensajes.eliminar(db, carla, mensaje_id)
    assert mensajes.obtener(db, clave_datos, beto, mensaje_id) is not None


def test_firma_detecta_alteracion_con_la_clave_maestra(db, clave_datos, ana, beto):
    mensaje_id = _enviar(db, clave_datos, ana)
    fila = _fila(db, mensaje_id)
    contexto = mensajes.contexto_mensaje(fila["remitente_id"], fila["destinatario_id"], mensaje_id, "cuerpo")
    db.execute(
        "UPDATE mensajes SET cuerpo_cifrado = ? WHERE id = ?",
        (simetrico.cifrar_texto("La clave es 0000", clave_datos, contexto), mensaje_id),
    )
    db.commit()

    msg = mensajes.obtener(db, clave_datos, beto, mensaje_id)
    assert msg.descifrable
    assert msg.cuerpo == "La clave es 0000"
    assert msg.estado_firma == mensajes.INVALIDA


def test_si_solo_se_altera_el_cuerpo_el_asunto_sigue_legible(db, clave_datos, ana, beto):
    mensaje_id = _enviar(db, clave_datos, ana, asunto="Asunto intacto")
    cifrado = _fila(db, mensaje_id)["cuerpo_cifrado"]
    prefijo, _, cuerpo = cifrado.rpartition(":")
    cambiado = ("B" if cuerpo[0] != "B" else "C") + cuerpo[1:]
    db.execute("UPDATE mensajes SET cuerpo_cifrado = ? WHERE id = ?", (f"{prefijo}:{cambiado}", mensaje_id))
    db.commit()

    msg = mensajes.obtener(db, clave_datos, beto, mensaje_id)
    assert msg.asunto == "Asunto intacto"
    assert not msg.descifrable
    assert msg.estado_firma == mensajes.INVALIDA


def test_un_cifrado_no_se_puede_trasplantar_a_otro_mensaje(db, clave_datos, ana, beto):
    primero = _enviar(db, clave_datos, ana, asunto="Primero", cuerpo="texto del primero")
    segundo = _enviar(db, clave_datos, ana, asunto="Segundo", cuerpo="texto del segundo")
    cifrado_primero = _fila(db, primero)["cuerpo_cifrado"]
    db.execute("UPDATE mensajes SET cuerpo_cifrado = ? WHERE id = ?", (cifrado_primero, segundo))
    db.commit()
    assert not mensajes.obtener(db, clave_datos, beto, segundo).descifrable


def test_eliminar_borra_el_mensaje_para_ambos(db, clave_datos, ana, beto):
    mensaje_id = _enviar(db, clave_datos, ana)
    mensajes.eliminar(db, beto, mensaje_id)
    with pytest.raises(NoEncontrado):
        mensajes.obtener(db, clave_datos, ana, mensaje_id)
    with pytest.raises(NoEncontrado):
        mensajes.obtener(db, clave_datos, beto, mensaje_id)


def test_no_se_puede_enviar_a_si_mismo_ni_a_un_usuario_inexistente(db, clave_datos, ana):
    with pytest.raises(ErrorServicio, match="a ti mismo"):
        _enviar(db, clave_datos, ana, destinatario="ana")
    with pytest.raises(ErrorServicio, match="no existe"):
        _enviar(db, clave_datos, ana, destinatario="nadie")
    with pytest.raises(ErrorServicio, match="contraseña"):
        _enviar(db, clave_datos, ana, destinatario="beto", contrasena="")


def test_comprobante_se_verifica_sin_la_aplicacion(db, clave_datos, ana, beto):
    mensaje_id = _enviar(db, clave_datos, ana, asunto="Confirmación", cuerpo="Confirmo la reunión")
    comprobante = mensajes.comprobante(db, clave_datos, beto, mensaje_id)
    clave = asimetrico.cargar_publica(comprobante["clave_publica_pem"])
    assert comprobantes.validar(comprobante, clave).valido

    alterado = json.loads(json.dumps(comprobante))
    alterado["payload"]["cuerpo"] = "Cancelo la reunión"
    resultado = comprobantes.validar(alterado, clave)
    assert not resultado.valido
    assert "alterado" in resultado.mensaje


def test_comprobante_con_clave_ajena_se_rechaza_como_falsificacion(db, clave_datos, ana, beto):
    mensaje_id = _enviar(db, clave_datos, ana)
    comprobante = mensajes.comprobante(db, clave_datos, beto, mensaje_id)
    clave_registrada = asimetrico.cargar_publica(comprobante["clave_publica_pem"])

    impostor = asimetrico.generar_par()
    falso = json.loads(json.dumps(comprobante))
    falso["clave_publica_pem"] = asimetrico.pem_publica(impostor.public_key())
    firma = asimetrico.firmar(impostor, comprobantes.mensaje_firmado(falso["payload"]))
    falso["firma"] = base64.b64encode(firma).decode("ascii")

    resultado = comprobantes.validar(falso, clave_registrada)
    assert not resultado.valido
    assert "falsificación" in resultado.mensaje


def test_no_se_emite_comprobante_si_la_firma_ya_no_es_valida(db, clave_datos, ana, beto):
    mensaje_id = _enviar(db, clave_datos, ana)
    fila = _fila(db, mensaje_id)
    contexto = mensajes.contexto_mensaje(fila["remitente_id"], fila["destinatario_id"], mensaje_id, "cuerpo")
    db.execute(
        "UPDATE mensajes SET cuerpo_cifrado = ? WHERE id = ?",
        (simetrico.cifrar_texto("texto cambiado", clave_datos, contexto), mensaje_id),
    )
    db.commit()
    with pytest.raises(ErrorServicio, match="ya no es válida"):
        mensajes.comprobante(db, clave_datos, beto, mensaje_id)


def test_comprobante_con_formato_invalido_se_rechaza(db):
    with pytest.raises(comprobantes.FormatoInvalido):
        comprobantes.validar({"formato": "otra-cosa"}, asimetrico.generar_par().public_key())
