"""Formato firmado y certificados verificables.

Un certificado contiene el texto firmado (payload), la firma Ed25519 y la clave pública
del autor. Quien lo reciba puede verificarlo sin acceder a la aplicación ni a su base de datos.
La verificación solo es fiable si la clave pública coincide con la registrada del autor.
"""

import base64
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from boveda.criptografia import asimetrico
from boveda.servicios.comun import ErrorServicio

VERSION = 1
FORMATO = "boveda-certificado"
CAMPOS_PAYLOAD = frozenset({"version", "documento", "autor", "titulo", "contenido", "creado_en", "firmado_en"})


class FormatoInvalido(ErrorServicio):
    pass


@dataclass(frozen=True)
class ResultadoVerificacion:
    valido: bool
    mensaje: str
    payload: dict


def construir_payload(documento_id: str, autor: str, titulo: str, contenido: str, creado_en: str, firmado_en: str) -> dict:
    return {
        "version": VERSION,
        "documento": documento_id,
        "autor": autor,
        "titulo": titulo,
        "contenido": contenido,
        "creado_en": creado_en,
        "firmado_en": firmado_en,
    }


def mensaje_firmado(payload: dict) -> bytes:
    return asimetrico.canonizar(payload)


def emitir(payload: dict, firma_b64: str, clave_publica_pem: str) -> dict:
    clave = asimetrico.cargar_publica(clave_publica_pem)
    return {
        "formato": FORMATO,
        "version": VERSION,
        "algoritmo": "Ed25519",
        "payload": payload,
        "firma": firma_b64,
        "clave_publica_pem": clave_publica_pem,
        "huella_clave_publica": asimetrico.huella(clave),
    }


def validar(certificado: dict, clave_confiable: Ed25519PublicKey) -> ResultadoVerificacion:
    try:
        if certificado.get("formato") != FORMATO:
            raise FormatoInvalido("El archivo no es un certificado de Bóveda")
        payload = certificado["payload"]
        firma = base64.b64decode(certificado["firma"], validate=True)
        clave_del_certificado = asimetrico.cargar_publica(certificado["clave_publica_pem"])
    except (KeyError, TypeError, ValueError, AttributeError) as e:
        raise FormatoInvalido("El certificado está incompleto o dañado") from e
    if not isinstance(payload, dict) or set(payload) != CAMPOS_PAYLOAD or payload["version"] != VERSION:
        raise FormatoInvalido("El contenido del certificado no tiene el formato esperado")
    if asimetrico.huella(clave_del_certificado) != asimetrico.huella(clave_confiable):
        return ResultadoVerificacion(
            False,
            "La clave pública del certificado no es la registrada del autor: posible falsificación",
            payload,
        )
    if not asimetrico.verificar(clave_confiable, firma, mensaje_firmado(payload)):
        return ResultadoVerificacion(False, "Firma inválida: el contenido fue alterado después de firmarse", payload)
    return ResultadoVerificacion(True, "Certificado auténtico: el documento no ha cambiado desde que se firmó", payload)
