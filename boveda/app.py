"""Fábrica de la aplicación Flask."""

from datetime import timedelta

from flask import Flask

from boveda import db
from boveda.config import Configuracion, ruta_relativa
from boveda.criptografia.claves import cargar_clave_maestra, derivar_subclave
from boveda.web import registrar_rutas


def crear_app(config: Configuracion | None = None) -> Flask:
    cfg = config or Configuracion.desde_entorno()
    clave = cargar_clave_maestra(cfg.clave_maestra_b64, cfg.ruta_clave)

    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=derivar_subclave(clave.valor, "sesion-web"),
        CLAVE_DATOS=derivar_subclave(clave.valor, "datos-mensajes"),
        CLAVE_ORIGEN=clave.origen,
        CLAVE_HUELLA=clave.huella,
        RUTA_BD=str(cfg.ruta_bd),
        RUTA_BD_VISIBLE=ruta_relativa(cfg.ruta_bd),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=cfg.cookies_seguras,
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=cfg.minutos_sesion),
        MAX_CONTENT_LENGTH=1024 * 1024,
    )
    db.inicializar(app)
    registrar_rutas(app)
    return app
