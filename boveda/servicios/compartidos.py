"""Enlaces públicos de solo lectura para compartir un mensaje.

El enlace es un token aleatorio de 256 bits. En la base se guarda solo su hash SHA-256,
nunca el token. El token se muestra una sola vez al crearlo. Cualquiera que lo tenga
puede leer el mensaje en /p/<token>; no puede editarlo ni firmar como el autor.
"""

import hashlib
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from boveda.servicios import mensajes
from boveda.servicios.comun import NoEncontrado, ahora_iso

DIAS_POR_DEFECTO = 7
TOKEN_BYTES = 32


@dataclass(frozen=True)
class EnlaceNuevo:
    id: str
    token: str
    expira_en: str


@dataclass(frozen=True)
class EnlacePublico:
    mensaje: mensajes.Mensaje
    creado_por: str
    creado_en: str
    expira_en: str


def crear_enlace(db, mensaje_id: str, usuario_id: str, dias: int = DIAS_POR_DEFECTO) -> EnlaceNuevo:
    if not 1 <= dias <= 30:
        raise ValueError("La duración del enlace debe estar entre 1 y 30 días")
    _exigir_participante(db, mensaje_id, usuario_id)
    token = secrets.token_urlsafe(TOKEN_BYTES)
    enlace_id = uuid.uuid4().hex
    creado_en = ahora_iso()
    expira_en = (datetime.now(timezone.utc) + timedelta(days=dias)).isoformat(timespec="seconds")
    db.execute(
        "INSERT INTO compartidos (id, mensaje_id, token_hash, creado_por, creado_en, expira_en) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (enlace_id, mensaje_id, _hash(token), usuario_id, creado_en, expira_en),
    )
    db.commit()
    return EnlaceNuevo(id=enlace_id, token=token, expira_en=expira_en)


def listar_enlaces(db, mensaje_id: str, usuario_id: str) -> list[dict]:
    _exigir_participante(db, mensaje_id, usuario_id)
    filas = db.execute(
        "SELECT id, creado_en, expira_en, revocado_en FROM compartidos WHERE mensaje_id = ? ORDER BY creado_en DESC",
        (mensaje_id,),
    ).fetchall()
    ahora = datetime.now(timezone.utc)
    return [
        {
            "id": fila["id"],
            "creado_en": fila["creado_en"],
            "expira_en": fila["expira_en"],
            "revocado_en": fila["revocado_en"],
            "activo": fila["revocado_en"] is None and datetime.fromisoformat(fila["expira_en"]) > ahora,
        }
        for fila in filas
    ]


def revocar_enlace(db, mensaje_id: str, enlace_id: str, usuario_id: str) -> None:
    fila = db.execute(
        "SELECT c.id FROM compartidos c JOIN mensajes m ON m.id = c.mensaje_id "
        "WHERE c.id = ? AND c.mensaje_id = ? AND (m.remitente_id = ? OR m.destinatario_id = ?)",
        (enlace_id, mensaje_id, usuario_id, usuario_id),
    ).fetchone()
    if fila is None:
        raise NoEncontrado("El enlace no existe")
    db.execute("UPDATE compartidos SET revocado_en = ? WHERE id = ?", (ahora_iso(), enlace_id))
    db.commit()


def resolver_enlace(db, clave: bytes, token: str) -> EnlacePublico:
    fila = db.execute(
        "SELECT c.*, u.nombre AS nombre_creador FROM compartidos c JOIN usuarios u ON u.id = c.creado_por "
        "WHERE c.token_hash = ?",
        (_hash(token),),
    ).fetchone()
    if fila is None or fila["revocado_en"] is not None:
        raise NoEncontrado("El enlace no está disponible")
    if datetime.fromisoformat(fila["expira_en"]) <= datetime.now(timezone.utc):
        raise NoEncontrado("El enlace no está disponible")
    mensaje = mensajes.obtener_por_id(db, clave, fila["mensaje_id"])
    return EnlacePublico(
        mensaje=mensaje,
        creado_por=fila["nombre_creador"],
        creado_en=fila["creado_en"],
        expira_en=fila["expira_en"],
    )


def _exigir_participante(db, mensaje_id: str, usuario_id: str) -> None:
    fila = db.execute(
        "SELECT id FROM mensajes WHERE id = ? AND (remitente_id = ? OR destinatario_id = ?)",
        (mensaje_id, usuario_id, usuario_id),
    ).fetchone()
    if fila is None:
        raise NoEncontrado("El mensaje no existe")


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()
