"""Configuración de Bóveda.

Nada sensible vive en el código: la clave maestra y las rutas se leen del entorno
o de archivos fuera de Git (ver docs/criptografia.md, sección "Gestión de llaves").
"""

import os
from dataclasses import dataclass
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent


def ruta_relativa(ruta: Path) -> str:
    try:
        return str(Path(ruta).resolve().relative_to(RAIZ))
    except ValueError:
        return Path(ruta).name


@dataclass
class Configuracion:
    ruta_bd: Path = RAIZ / "data" / "boveda.db"
    clave_maestra_b64: str | None = None
    ruta_clave: Path = RAIZ / "secretos" / "clave_maestra.key"
    host: str = "127.0.0.1"
    puerto: int = 5000
    cookies_seguras: bool = False
    minutos_sesion: int = 60

    @classmethod
    def desde_entorno(cls) -> "Configuracion":
        env = os.environ
        return cls(
            ruta_bd=Path(env.get("BOVEDA_BASE_DATOS") or RAIZ / "data" / "boveda.db"),
            clave_maestra_b64=env.get("BOVEDA_CLAVE_MAESTRA") or None,
            ruta_clave=Path(env.get("BOVEDA_CLAVE_ARCHIVO") or RAIZ / "secretos" / "clave_maestra.key"),
            host=env.get("BOVEDA_HOST") or "127.0.0.1",
            puerto=int(env.get("BOVEDA_PUERTO") or 5000),
            cookies_seguras=env.get("BOVEDA_COOKIES_SEGURAS") == "1",
        )
