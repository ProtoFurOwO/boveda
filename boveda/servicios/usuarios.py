"""Cuentas de usuario: alta, autenticación y desbloqueo de la llave de firma.

Al registrarse, cada usuario recibe un par de llaves Ed25519. La llave privada se guarda
cifrada con AES-256-GCM usando una clave derivada de su contraseña (scrypt + sal propia).
Sin la contraseña no hay forma de abrirla, ni siquiera para el servidor.
"""

import base64
import functools
import re
import secrets
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from boveda.criptografia import asimetrico, contrasenas, simetrico
from boveda.servicios.comun import ContrasenaIncorrecta, ErrorServicio, ahora_iso

NOMBRE_VALIDO = re.compile(r"[a-z0-9_.-]{3,32}")
CONTRASENA_MIN = 10
CONTRASENA_MAX = 128


def registrar(db, nombre: str, contrasena: str) -> str:
    nombre = nombre.strip().lower()
    _validar(nombre, contrasena)
    if buscar_por_nombre(db, nombre) is not None:
        raise ErrorServicio("Ese nombre de usuario ya está en uso")
    usuario_id = uuid.uuid4().hex
    llave = asimetrico.generar_par()
    sal_llave = secrets.token_bytes(16)
    kek = contrasenas.derivar_clave_envoltura(contrasena, sal_llave)
    db.execute(
        "INSERT INTO usuarios (id, nombre, hash_contrasena, sal_llave, clave_publica_pem, clave_privada_cifrada, creado_en) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            usuario_id,
            nombre,
            contrasenas.crear_hash(contrasena),
            base64.b64encode(sal_llave).decode("ascii"),
            asimetrico.pem_publica(llave.public_key()),
            asimetrico.envolver_llave_privada(llave, kek, _contexto_llave(usuario_id)),
            ahora_iso(),
        ),
    )
    db.commit()
    return usuario_id


def autenticar(db, nombre: str, contrasena: str):
    fila = buscar_por_nombre(db, nombre)
    if fila is None:
        contrasenas.verificar_hash(contrasena, _hash_senuelo())
        return None
    return fila if contrasenas.verificar_hash(contrasena, fila["hash_contrasena"]) else None


def buscar_por_id(db, usuario_id: str):
    return db.execute("SELECT * FROM usuarios WHERE id = ?", (usuario_id,)).fetchone()


def listar(db):
    return db.execute("SELECT * FROM usuarios ORDER BY nombre").fetchall()


def buscar_por_nombre(db, nombre: str):
    return db.execute("SELECT * FROM usuarios WHERE nombre = ?", (nombre.strip().lower(),)).fetchone()


def desbloquear_llave_firma(fila, contrasena: str) -> Ed25519PrivateKey:
    kek = contrasenas.derivar_clave_envoltura(contrasena, base64.b64decode(fila["sal_llave"]))
    try:
        return asimetrico.desenvolver_llave_privada(fila["clave_privada_cifrada"], kek, _contexto_llave(fila["id"]))
    except simetrico.ErrorCifrado as e:
        raise ContrasenaIncorrecta("Contraseña incorrecta: no se pudo desbloquear tu llave de firma") from e


def _contexto_llave(usuario_id: str) -> bytes:
    return f"llave-firma|{usuario_id}".encode("utf-8")


@functools.lru_cache(maxsize=1)
def _hash_senuelo() -> str:
    """Hash falso para que un usuario inexistente tarde lo mismo que uno real."""
    return contrasenas.crear_hash(secrets.token_hex(16))


def _validar(nombre: str, contrasena: str) -> None:
    if not NOMBRE_VALIDO.fullmatch(nombre):
        raise ErrorServicio("El usuario debe tener de 3 a 32 caracteres: letras, números, punto, guion o guion bajo")
    if not CONTRASENA_MIN <= len(contrasena) <= CONTRASENA_MAX:
        raise ErrorServicio(f"La contraseña debe tener entre {CONTRASENA_MIN} y {CONTRASENA_MAX} caracteres")
