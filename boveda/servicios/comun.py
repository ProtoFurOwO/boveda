"""Errores de negocio y utilidades compartidas por los servicios."""

from datetime import datetime, timezone


class ErrorServicio(Exception):
    """Falla controlada cuyo mensaje puede mostrarse tal cual al usuario."""


class NoEncontrado(ErrorServicio):
    pass


class ContrasenaIncorrecta(ErrorServicio):
    pass


def ahora_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
