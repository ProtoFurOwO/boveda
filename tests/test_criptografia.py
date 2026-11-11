import base64
import secrets

import pytest

from boveda.criptografia import asimetrico, claves, simetrico


def _clave():
    return secrets.token_bytes(32)


def test_cifrado_y_descifrado_restauran_el_texto():
    clave, contexto = _clave(), b"documento|1"
    cifrado = simetrico.cifrar_texto("NIP de la cuenta: 4321 ñandú", clave, contexto)
    assert simetrico.descifrar_texto(cifrado, clave, contexto) == "NIP de la cuenta: 4321 ñandú"


def test_el_texto_en_claro_no_aparece_en_el_cifrado():
    cifrado = simetrico.cifrar_texto("secreto-muy-visible", _clave(), b"ctx")
    assert "secreto" not in cifrado
    assert cifrado.startswith("v1:")


def test_el_mismo_texto_produce_cifrados_distintos():
    clave = _clave()
    assert simetrico.cifrar_texto("igual", clave, b"c") != simetrico.cifrar_texto("igual", clave, b"c")


def test_clave_incorrecta_no_descifra():
    cifrado = simetrico.cifrar_texto("dato", _clave(), b"c")
    with pytest.raises(simetrico.ErrorCifrado):
        simetrico.descifrar_texto(cifrado, _clave(), b"c")


def test_contexto_distinto_no_descifra():
    clave = _clave()
    cifrado = simetrico.cifrar_texto("dato", clave, b"documento|a|titulo")
    with pytest.raises(simetrico.ErrorCifrado):
        simetrico.descifrar_texto(cifrado, clave, b"documento|a|contenido")


def test_cualquier_alteracion_del_cifrado_se_detecta():
    clave, contexto = _clave(), b"c"
    version, nonce, cifrado = simetrico.cifrar_texto("dato", clave, contexto).split(":")
    cambiado = ("B" if cifrado[0] != "B" else "C") + cifrado[1:]
    with pytest.raises(simetrico.ErrorCifrado):
        simetrico.descifrar_texto(f"{version}:{nonce}:{cambiado}", clave, contexto)


def test_version_desconocida_se_rechaza():
    clave, contexto = _clave(), b"c"
    cifrado = simetrico.cifrar_texto("dato", clave, contexto).replace("v1:", "v9:", 1)
    with pytest.raises(simetrico.ErrorCifrado, match="Versión"):
        simetrico.descifrar_texto(cifrado, clave, contexto)


def test_clave_de_longitud_invalida_se_rechaza():
    with pytest.raises(ValueError):
        simetrico.cifrar_texto("dato", b"corta", b"c")


def test_firma_detecta_cambios_y_rechaza_claves_ajenas():
    llave = asimetrico.generar_par()
    mensaje = b"contrato: pagar 100"
    firma = asimetrico.firmar(llave, mensaje)
    assert asimetrico.verificar(llave.public_key(), firma, mensaje)
    assert not asimetrico.verificar(llave.public_key(), firma, b"contrato: pagar 900")
    assert not asimetrico.verificar(asimetrico.generar_par().public_key(), firma, mensaje)


def test_llave_privada_solo_se_abre_con_la_kek_correcta():
    llave = asimetrico.generar_par()
    kek = _clave()
    envuelta = asimetrico.envolver_llave_privada(llave, kek, b"llave-firma|usuario")
    abierta = asimetrico.desenvolver_llave_privada(envuelta, kek, b"llave-firma|usuario")
    assert asimetrico.verificar(llave.public_key(), abierta.sign(b"x"), b"x")
    with pytest.raises(simetrico.ErrorCifrado):
        asimetrico.desenvolver_llave_privada(envuelta, _clave(), b"llave-firma|usuario")


def test_canonizar_ignora_el_orden_de_las_llaves():
    assert asimetrico.canonizar({"b": 1, "a": "ñ"}) == asimetrico.canonizar({"a": "ñ", "b": 1})


def test_pem_y_huella_reconstruyen_la_clave_publica():
    clave = asimetrico.generar_par().public_key()
    recuperada = asimetrico.cargar_publica(asimetrico.pem_publica(clave))
    assert asimetrico.huella(recuperada) == asimetrico.huella(clave)


def test_clave_maestra_desde_variable_de_entorno_tiene_prioridad(tmp_path):
    archivo = tmp_path / "clave.key"
    archivo.write_text(base64.b64encode(_clave()).decode("ascii") + "\n", encoding="ascii")
    env = base64.b64encode(_clave()).decode("ascii")
    clave = claves.cargar_clave_maestra(env, archivo)
    assert clave.valor == base64.b64decode(env)
    assert clave.origen == claves.ORIGEN_ENTORNO


def test_clave_maestra_se_lee_del_archivo_si_no_hay_variable(tmp_path):
    contenido = base64.b64encode(_clave()).decode("ascii")
    archivo = tmp_path / "clave.key"
    archivo.write_text(contenido + "\n", encoding="ascii")
    clave = claves.cargar_clave_maestra(None, archivo)
    assert clave.valor == base64.b64decode(contenido)
    assert clave.origen.startswith("archivo protegido")


def test_clave_maestra_se_genera_en_el_primer_arranque_y_se_reutiliza(tmp_path):
    archivo = tmp_path / "secretos" / "clave_maestra.key"
    primera = claves.cargar_clave_maestra(None, archivo)
    assert archivo.exists()
    assert len(primera.valor) == 32
    assert primera.origen.startswith("archivo generado")
    assert claves.cargar_clave_maestra(None, archivo).valor == primera.valor


def test_clave_maestra_invalida_se_rechaza_sin_revelarla(tmp_path):
    corta = base64.b64encode(b"corta").decode("ascii")
    with pytest.raises(claves.ErrorClave) as error:
        claves.cargar_clave_maestra(corta, tmp_path / "x.key")
    assert corta not in str(error.value)


def test_subclaves_son_deterministas_y_separadas_por_proposito():
    maestra = _clave()
    datos = claves.derivar_subclave(maestra, "datos-documentos")
    assert datos == claves.derivar_subclave(maestra, "datos-documentos")
    assert datos != claves.derivar_subclave(maestra, "sesion-web")
    assert datos != maestra
