"""Capa de seguridad web: sesión, protección CSRF, cabeceras HTTP y errores."""

import hmac
import secrets
from datetime import datetime

from flask import Flask, abort, g, render_template, request, session
from werkzeug.exceptions import HTTPException

from boveda.db import obtener_db
from boveda.servicios import usuarios

POLITICA_CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "form-action 'self'; frame-ancestors 'none'; base-uri 'self'"
)


def formatear_fecha(iso: str | None) -> str:
    if not iso:
        return "—"
    return datetime.fromisoformat(iso).astimezone().strftime("%d/%m/%Y %H:%M")


def formatear_huella(huella: str) -> str:
    return " ".join(huella[i : i + 4] for i in range(0, len(huella), 4))


def instalar(app: Flask) -> None:
    app.add_template_filter(formatear_fecha, "fecha")
    app.add_template_filter(formatear_huella, "huella")
    app.jinja_env.globals["csrf_token"] = lambda: session.get("csrf", "")

    @app.context_processor
    def _contexto():
        return {"usuario": g.get("usuario")}

    @app.before_request
    def _preparar_peticion():
        g.usuario = None
        usuario_id = session.get("usuario_id")
        if usuario_id:
            g.usuario = usuarios.buscar_por_id(obtener_db(), usuario_id)
            if g.usuario is None:
                session.clear()
        if request.method == "POST" and not _token_valido():
            abort(400, description="El formulario caducó o no es válido. Recarga la página e inténtalo de nuevo.")
        session.setdefault("csrf", secrets.token_urlsafe(32))

    @app.after_request
    def _cabeceras(respuesta):
        respuesta.headers["Content-Security-Policy"] = POLITICA_CSP
        respuesta.headers["X-Content-Type-Options"] = "nosniff"
        respuesta.headers["X-Frame-Options"] = "DENY"
        respuesta.headers["Referrer-Policy"] = "same-origin"
        respuesta.headers["Cache-Control"] = "no-store"
        return respuesta

    @app.errorhandler(HTTPException)
    def _error_http(error):
        return render_template("error.html", codigo=error.code, titulo=error.name, mensaje=error.description), error.code


def _token_valido() -> bool:
    enviado = request.form.get("csrf_token", "")
    esperado = session.get("csrf", "")
    return bool(esperado) and hmac.compare_digest(enviado.encode("utf-8"), esperado.encode("utf-8"))
