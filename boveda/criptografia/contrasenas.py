"""Contraseñas con scrypt (RFC 7914) con los parámetros recomendados por OWASP: N=2^17, r=8, p=1.

scrypt consume memoria y CPU a propósito: encarece la adivinanza masiva si alguien roba la
base de datos. Tiene dos usos independientes, cada uno con su propia sal:
- crear_hash / verificar_hash: comprobar la contraseña al iniciar sesión.
- derivar_clave_envoltura: obtener la clave (KEK) que abre la llave privada de firma.
"""

import base64
import secrets

from cryptography.exceptions import InvalidKey
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

N = 2**17
R = 8
P = 1
LONGITUD = 32
SAL_BYTES = 16


def _kdf(sal: bytes, n: int, r: int, p: int) -> Scrypt:
    return Scrypt(salt=sal, length=LONGITUD, n=n, r=r, p=p)


def crear_hash(contrasena: str) -> str:
    sal = secrets.token_bytes(SAL_BYTES)
    digesto = _kdf(sal, N, R, P).derive(contrasena.encode("utf-8"))
    return f"scrypt${N}${R}${P}${_b64(sal)}${_b64(digesto)}"


def verificar_hash(contrasena: str, almacenado: str) -> bool:
    try:
        _, n, r, p, sal, digesto = almacenado.split("$")
        _kdf(_unb64(sal), int(n), int(r), int(p)).verify(contrasena.encode("utf-8"), _unb64(digesto))
    except (ValueError, InvalidKey):
        return False
    return True


def derivar_clave_envoltura(contrasena: str, sal: bytes) -> bytes:
    return _kdf(sal, N, R, P).derive(contrasena.encode("utf-8"))


def _b64(datos: bytes) -> str:
    return base64.b64encode(datos).decode("ascii")


def _unb64(texto: str) -> bytes:
    return base64.b64decode(texto, validate=True)
