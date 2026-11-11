import base64
import json

import pytest

from boveda.criptografia import asimetrico, simetrico
from boveda.servicios import certificados, documentos, usuarios
from boveda.servicios.comun import ContrasenaIncorrecta, ErrorServicio, NoEncontrado

CONTRASENA = "contraseña-segura-1"


@pytest.fixture
def ana(db):
    return usuarios.registrar(db, "Ana", CONTRASENA)


def _crear(db, clave, usuario_id, titulo="Contrato", contenido="Pagar 100 pesos"):
    return documentos.crear(db, clave, usuario_id, titulo, contenido)


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


def test_documento_se_guarda_cifrado_y_se_lee_en_claro(db, clave_datos, ana):
    doc_id = _crear(db, clave_datos, ana, "Clave del banco", "NIP 4321")
    bruto = db.execute("SELECT * FROM documentos WHERE id = ?", (doc_id,)).fetchone()
    assert "banco" not in bruto["titulo_cifrado"]
    assert "4321" not in bruto["contenido_cifrado"]
    doc = documentos.obtener(db, clave_datos, ana, doc_id)
    assert (doc.titulo, doc.contenido) == ("Clave del banco", "NIP 4321")
    assert doc.estado_firma == documentos.SIN_FIRMA


def test_firmar_exige_la_contrasena_correcta(db, clave_datos, ana):
    doc_id = _crear(db, clave_datos, ana)
    with pytest.raises(ContrasenaIncorrecta):
        documentos.firmar(db, clave_datos, ana, doc_id, "otra-contrasena-123")
    assert documentos.obtener(db, clave_datos, ana, doc_id).estado_firma == documentos.SIN_FIRMA


def test_firma_valida_y_se_detecta_alteracion_con_la_clave_maestra(db, clave_datos, ana):
    doc_id = _crear(db, clave_datos, ana)
    documentos.firmar(db, clave_datos, ana, doc_id, CONTRASENA)
    assert documentos.obtener(db, clave_datos, ana, doc_id).estado_firma == documentos.VALIDA

    # Un atacante con la clave maestra re-cifra otro texto: AES-GCM lo acepta, la firma no.
    contexto = documentos.contexto_documento(ana, doc_id, "contenido")
    db.execute(
        "UPDATE documentos SET contenido_cifrado = ? WHERE id = ?",
        (simetrico.cifrar_texto("Pagar 900 pesos", clave_datos, contexto), doc_id),
    )
    db.commit()
    doc = documentos.obtener(db, clave_datos, ana, doc_id)
    assert doc.descifrable
    assert doc.contenido == "Pagar 900 pesos"
    assert doc.estado_firma == documentos.INVALIDA


def test_alterar_bytes_del_cifrado_se_detecta_con_aes_gcm(db, clave_datos, ana):
    doc_id = _crear(db, clave_datos, ana)
    cifrado = db.execute("SELECT contenido_cifrado FROM documentos WHERE id = ?", (doc_id,)).fetchone()[0]
    prefijo, _, cuerpo = cifrado.rpartition(":")
    cambiado = ("B" if cuerpo[0] != "B" else "C") + cuerpo[1:]
    db.execute("UPDATE documentos SET contenido_cifrado = ? WHERE id = ?", (f"{prefijo}:{cambiado}", doc_id))
    db.commit()
    doc = documentos.obtener(db, clave_datos, ana, doc_id)
    assert not doc.descifrable
    assert doc.estado_firma == documentos.INVALIDA


def test_si_solo_se_altera_el_contenido_el_titulo_sigue_legible(db, clave_datos, ana):
    doc_id = _crear(db, clave_datos, ana, "Título intacto", "texto alterado")
    cifrado = db.execute("SELECT contenido_cifrado FROM documentos WHERE id = ?", (doc_id,)).fetchone()[0]
    prefijo, _, cuerpo = cifrado.rpartition(":")
    cambiado = ("B" if cuerpo[0] != "B" else "C") + cuerpo[1:]
    db.execute("UPDATE documentos SET contenido_cifrado = ? WHERE id = ?", (f"{prefijo}:{cambiado}", doc_id))
    db.commit()
    doc = documentos.obtener(db, clave_datos, ana, doc_id)
    assert doc.titulo == "Título intacto"
    assert not doc.descifrable
    assert doc.estado_firma == documentos.INVALIDA


def test_editar_invalida_la_firma_solo_si_hubo_cambios(db, clave_datos, ana):
    doc_id = _crear(db, clave_datos, ana)
    documentos.firmar(db, clave_datos, ana, doc_id, CONTRASENA)
    assert documentos.actualizar(db, clave_datos, ana, doc_id, "Contrato", "Pagar 100 pesos") is False
    assert documentos.obtener(db, clave_datos, ana, doc_id).estado_firma == documentos.VALIDA
    assert documentos.actualizar(db, clave_datos, ana, doc_id, "Contrato", "Pagar 900 pesos") is True
    assert documentos.obtener(db, clave_datos, ana, doc_id).estado_firma == documentos.SIN_FIRMA


def test_los_documentos_de_otro_usuario_no_son_accesibles(db, clave_datos, ana):
    beto = usuarios.registrar(db, "beto", CONTRASENA)
    doc_id = _crear(db, clave_datos, ana)
    with pytest.raises(NoEncontrado):
        documentos.obtener(db, clave_datos, beto, doc_id)
    with pytest.raises(NoEncontrado):
        documentos.eliminar(db, beto, doc_id)


def test_un_cifrado_no_se_puede_trasplantar_a_otro_documento(db, clave_datos, ana):
    origen = _crear(db, clave_datos, ana, "Origen", "texto del origen")
    destino = _crear(db, clave_datos, ana, "Destino", "texto del destino")
    cifrado_origen = db.execute("SELECT contenido_cifrado FROM documentos WHERE id = ?", (origen,)).fetchone()[0]
    db.execute("UPDATE documentos SET contenido_cifrado = ? WHERE id = ?", (cifrado_origen, destino))
    db.commit()
    assert not documentos.obtener(db, clave_datos, ana, destino).descifrable


def test_certificado_se_verifica_sin_la_aplicacion(db, clave_datos, ana):
    doc_id = _crear(db, clave_datos, ana)
    documentos.firmar(db, clave_datos, ana, doc_id, CONTRASENA)
    cert = documentos.certificado(db, clave_datos, ana, doc_id)
    clave = asimetrico.cargar_publica(cert["clave_publica_pem"])
    assert certificados.validar(cert, clave).valido

    alterado = json.loads(json.dumps(cert))
    alterado["payload"]["contenido"] = "Pagar 900 pesos"
    resultado = certificados.validar(alterado, clave)
    assert not resultado.valido
    assert "alterado" in resultado.mensaje


def test_certificado_con_clave_ajena_se_rechaza_como_falsificacion(db, clave_datos, ana):
    doc_id = _crear(db, clave_datos, ana)
    documentos.firmar(db, clave_datos, ana, doc_id, CONTRASENA)
    cert = documentos.certificado(db, clave_datos, ana, doc_id)
    clave_registrada = asimetrico.cargar_publica(cert["clave_publica_pem"])
    impostor = asimetrico.generar_par()
    cert_falso = json.loads(json.dumps(cert))
    cert_falso["clave_publica_pem"] = asimetrico.pem_publica(impostor.public_key())
    firma = asimetrico.firmar(impostor, certificados.mensaje_firmado(cert_falso["payload"]))
    cert_falso["firma"] = base64.b64encode(firma).decode("ascii")
    resultado = certificados.validar(cert_falso, clave_registrada)
    assert not resultado.valido
    assert "falsificación" in resultado.mensaje


def test_no_se_emite_certificado_de_un_documento_sin_firma(db, clave_datos, ana):
    doc_id = _crear(db, clave_datos, ana)
    with pytest.raises(ErrorServicio, match="Firma el documento"):
        documentos.certificado(db, clave_datos, ana, doc_id)


def test_certificado_con_formato_invalido_se_rechaza(db):
    with pytest.raises(certificados.FormatoInvalido):
        certificados.validar({"formato": "otra-cosa"}, asimetrico.generar_par().public_key())
