"""Cifrado simétrico de datos en reposo con AES-256-GCM (NIST SP 800-38D).

AES-GCM es un cifrado autenticado (AEAD): además de ocultar el texto, detecta cualquier
modificación del cifrado. Cada cifrado usa un nonce aleatorio de 96 bits. Los datos
asociados (contexto) se autentican sin cifrarse: así un cifrado no puede trasladarse a
otro documento o campo sin que el descifrado falle.

Formato almacenado: "v1:<nonce en base64>:<cifrado y etiqueta en base64>"
"""

import base64
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

VERSION = "v1"
LONGITUD_CLAVE = 32
LONGITUD_NONCE = 12


class ErrorCifrado(Exception):
    pass


def cifrar_bytes(datos: bytes, clave: bytes, contexto: bytes) -> str:
    _validar_clave(clave)
    nonce = secrets.token_bytes(LONGITUD_NONCE)
    cifrado = AESGCM(clave).encrypt(nonce, datos, contexto)
    return f"{VERSION}:{_b64(nonce)}:{_b64(cifrado)}"


def descifrar_bytes(almacenado: str, clave: bytes, contexto: bytes) -> bytes:
    _validar_clave(clave)
    try:
        version, nonce, cifrado = almacenado.split(":")
    except ValueError as e:
        raise ErrorCifrado("El dato cifrado tiene un formato inválido") from e
    if version != VERSION:
        raise ErrorCifrado(f"Versión de cifrado no soportada: {version}")
    try:
        return AESGCM(clave).decrypt(_unb64(nonce), _unb64(cifrado), contexto)
    except (ValueError, InvalidTag) as e:
        raise ErrorCifrado("No se pudo descifrar: el dato fue alterado o la clave o el contexto no coinciden") from e


def cifrar_texto(texto: str, clave: bytes, contexto: bytes) -> str:
    return cifrar_bytes(texto.encode("utf-8"), clave, contexto)


def descifrar_texto(almacenado: str, clave: bytes, contexto: bytes) -> str:
    return descifrar_bytes(almacenado, clave, contexto).decode("utf-8")


def _validar_clave(clave: bytes) -> None:
    if len(clave) != LONGITUD_CLAVE:
        raise ValueError("La clave AES-256 debe medir 32 bytes")


def _b64(datos: bytes) -> str:
    return base64.b64encode(datos).decode("ascii")


def _unb64(texto: str) -> bytes:
    return base64.b64decode(texto, validate=True)
