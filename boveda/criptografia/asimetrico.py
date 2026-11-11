"""Firma digital asimétrica con Ed25519 (RFC 8032).

Cada usuario tiene un par de llaves:
- La llave pública se registra y puede compartirse; sirve para verificar firmas.
- La llave privada firma. Nunca se guarda en claro: se cifra con AES-256-GCM (simetrico.py)
  usando una clave de envoltura (KEK) derivada de la contraseña del usuario con scrypt.

Lo firmado es una representación canónica (JSON con claves ordenadas y sin espacios),
para que firma y verificación calculen exactamente los mismos bytes.
"""

import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from boveda.criptografia import simetrico


def generar_par() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def envolver_llave_privada(llave: Ed25519PrivateKey, kek: bytes, contexto: bytes) -> str:
    der = llave.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return simetrico.cifrar_bytes(der, kek, contexto)


def desenvolver_llave_privada(envuelta: str, kek: bytes, contexto: bytes) -> Ed25519PrivateKey:
    der = simetrico.descifrar_bytes(envuelta, kek, contexto)
    llave = serialization.load_der_private_key(der, password=None)
    if not isinstance(llave, Ed25519PrivateKey):
        raise simetrico.ErrorCifrado("La llave descifrada no es Ed25519")
    return llave


def pem_publica(clave: Ed25519PublicKey) -> str:
    return clave.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")


def cargar_publica(pem: str) -> Ed25519PublicKey:
    try:
        clave = serialization.load_pem_public_key(pem.encode("ascii"))
    except ValueError as e:
        raise ValueError("La clave pública PEM no es válida") from e
    if not isinstance(clave, Ed25519PublicKey):
        raise ValueError("La clave pública no es Ed25519")
    return clave


def huella(clave: Ed25519PublicKey) -> str:
    der = clave.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def firmar(llave: Ed25519PrivateKey, mensaje: bytes) -> bytes:
    return llave.sign(mensaje)


def verificar(clave: Ed25519PublicKey, firma: bytes, mensaje: bytes) -> bool:
    try:
        clave.verify(firma, mensaje)
    except InvalidSignature:
        return False
    return True


def canonizar(datos: dict) -> bytes:
    return json.dumps(datos, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
