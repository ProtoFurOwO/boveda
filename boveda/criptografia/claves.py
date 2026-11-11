"""Clave maestra y derivación de subclaves.

La clave maestra es el único secreto raíz de la aplicación: 256 bits aleatorios.
Se resuelve en este orden y nunca se guarda en la base de datos ni en el código:

1. Variable de entorno BOVEDA_CLAVE_MAESTRA (servidores y gestores de secretos).
2. Archivo protegido BOVEDA_CLAVE_ARCHIVO (por defecto secretos/clave_maestra.key, ignorado por Git).
3. Si no existe ninguna, se genera en el primer arranque y se guarda en ese archivo.

De la clave maestra se derivan subclaves con HKDF, una por propósito (separación de claves).
"""

import base64
import getpass
import hashlib
import logging
import os
import secrets
import subprocess
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from boveda.config import ruta_relativa

LONGITUD_BYTES = 32
ORIGEN_ENTORNO = "variable de entorno BOVEDA_CLAVE_MAESTRA"

log = logging.getLogger(__name__)


class ErrorClave(Exception):
    pass


@dataclass(frozen=True)
class ClaveMaestra:
    valor: bytes
    origen: str
    huella: str


def cargar_clave_maestra(clave_b64: str | None, ruta: Path) -> ClaveMaestra:
    if clave_b64:
        valor = _decodificar(clave_b64, "BOVEDA_CLAVE_MAESTRA")
        return ClaveMaestra(valor, ORIGEN_ENTORNO, _huella(valor))
    if ruta.exists():
        valor = _decodificar(ruta.read_text(encoding="ascii"), ruta_relativa(ruta))
        return ClaveMaestra(valor, f"archivo protegido {ruta_relativa(ruta)}", _huella(valor))
    valor = secrets.token_bytes(LONGITUD_BYTES)
    _escribir_protegido(ruta, base64.b64encode(valor).decode("ascii"))
    log.warning("No había clave maestra: se generó una nueva en %s. Respáldala fuera del proyecto.", ruta_relativa(ruta))
    return ClaveMaestra(valor, f"archivo generado en el primer arranque ({ruta_relativa(ruta)})", _huella(valor))


def derivar_subclave(clave_maestra: bytes, proposito: str) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=LONGITUD_BYTES,
        salt=None,
        info=f"boveda/{proposito}".encode("utf-8"),
    ).derive(clave_maestra)


def _decodificar(texto: str, fuente: str) -> bytes:
    try:
        valor = base64.b64decode(texto.strip(), validate=True)
    except ValueError as e:
        raise ErrorClave(f"La clave en {fuente} no está en base64") from e
    if len(valor) != LONGITUD_BYTES:
        raise ErrorClave(f"La clave en {fuente} debe medir {LONGITUD_BYTES} bytes (256 bits)")
    return valor


def _huella(valor: bytes) -> str:
    return hashlib.sha256(valor).hexdigest()[:16]


def _escribir_protegido(ruta: Path, contenido: str) -> None:
    ruta.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(ruta, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as archivo:
        archivo.write(contenido + "\n")
    _restringir_acceso(ruta)


def _restringir_acceso(ruta: Path) -> None:
    if os.name != "nt":
        os.chmod(ruta, 0o600)
        return
    resultado = subprocess.run(
        ["icacls", str(ruta), "/inheritance:r", "/grant:r", f"{getpass.getuser()}:F"],
        capture_output=True,
    )
    if resultado.returncode != 0:
        log.warning("No se pudieron restringir los permisos de %s con icacls", ruta)
