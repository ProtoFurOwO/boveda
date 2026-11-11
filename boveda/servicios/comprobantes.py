"""Comprobantes de mensajes: el texto firmado, la firma y la clave pública del remitente.

Un comprobante permite que un tercero verifique un mensaje sin acceder a la aplicación
ni a su base de datos. La verificación solo es fiable si la clave pública coincide con la
registrada del remitente.
"""

import base64
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from boveda.criptografia import asimetrico
from boveda.servicios.comun import ErrorServicio

VERSION = 1
FORMATO = "boveda-comprobante"
CAMPOS_PAYLOAD = frozenset(
    {"version", "mensaje", "remitente", "destinatario", "asunto", "cuerpo", "creado_en", "firmado_en"}
)


class FormatoInvalido(ErrorServicio):
    pass


@dataclass(frozen=True)
class ResultadoVerificacion:
    valido: bool
    mensaje: str
    payload: dict


def construir_payload(
    mensaje_id: str, remitente: str, destinatario: str, asunto: str, cuerpo: str, creado_en: str, firmado_en: str
) -> dict:
    return {
        "version": VERSION,
        "mensaje": mensaje_id,
        "remitente": remitente,
        "destinatario": destinatario,
        "asunto": asunto,
        "cuerpo": cuerpo,
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


def validar(comprobante: dict, clave_confiable: Ed25519PublicKey) -> ResultadoVerificacion:
    try:
        if comprobante.get("formato") != FORMATO:
            raise FormatoInvalido("El archivo no es un comprobante de Bóveda")
        payload = comprobante["payload"]
        firma = base64.b64decode(comprobante["firma"], validate=True)
        clave_del_comprobante = asimetrico.cargar_publica(comprobante["clave_publica_pem"])
    except (KeyError, TypeError, ValueError, AttributeError) as e:
        raise FormatoInvalido("El comprobante está incompleto o dañado") from e
    if not isinstance(payload, dict) or set(payload) != CAMPOS_PAYLOAD or payload["version"] != VERSION:
        raise FormatoInvalido("El contenido del comprobante no tiene el formato esperado")
    if asimetrico.huella(clave_del_comprobante) != asimetrico.huella(clave_confiable):
        return ResultadoVerificacion(
            False,
            "La clave pública del comprobante no es la registrada del remitente: posible falsificación",
            payload,
        )
    if not asimetrico.verificar(clave_confiable, firma, mensaje_firmado(payload)):
        return ResultadoVerificacion(False, "Firma inválida: el mensaje fue alterado después de firmarse", payload)
    return ResultadoVerificacion(True, "Comprobante auténtico: el mensaje no ha cambiado desde que se envió", payload)
