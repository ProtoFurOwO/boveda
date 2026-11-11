"""Capa web: rutas Flask y plantillas."""

from flask import Flask


def registrar_rutas(app: Flask) -> None:
    from boveda.web import auth, mensajes, publico, seguridad

    seguridad.instalar(app)
    app.register_blueprint(auth.bp)
    app.register_blueprint(mensajes.bp)
    app.register_blueprint(publico.bp)
