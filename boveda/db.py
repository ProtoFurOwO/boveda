"""Conexión y esquema de SQLite.

Todo lo cifrado se guarda como texto ("v1:<nonce>:<cifrado>"), así que la base de datos
nunca contiene asuntos, mensajes ni llaves privadas en claro.
"""

import contextlib
import sqlite3
from pathlib import Path

from flask import Flask, current_app, g

ESQUEMA = """
CREATE TABLE IF NOT EXISTS usuarios (
    id                    TEXT PRIMARY KEY,
    nombre                TEXT NOT NULL UNIQUE,
    hash_contrasena       TEXT NOT NULL,
    sal_llave             TEXT NOT NULL,
    clave_publica_pem     TEXT NOT NULL,
    clave_privada_cifrada TEXT NOT NULL,
    creado_en             TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS mensajes (
    id               TEXT PRIMARY KEY,
    remitente_id     TEXT NOT NULL REFERENCES usuarios(id),
    destinatario_id  TEXT NOT NULL REFERENCES usuarios(id),
    asunto_cifrado   TEXT NOT NULL,
    cuerpo_cifrado   TEXT NOT NULL,
    creado_en        TEXT NOT NULL,
    firma            TEXT,
    firmado_en       TEXT
);

CREATE INDEX IF NOT EXISTS idx_mensajes_destinatario ON mensajes(destinatario_id);
CREATE INDEX IF NOT EXISTS idx_mensajes_remitente ON mensajes(remitente_id);
"""


def conectar(ruta: str | Path) -> sqlite3.Connection:
    Path(ruta).parent.mkdir(parents=True, exist_ok=True)
    conexion = sqlite3.connect(ruta)
    conexion.row_factory = sqlite3.Row
    conexion.execute("PRAGMA foreign_keys = ON")
    return conexion


def crear_esquema(conexion: sqlite3.Connection) -> None:
    conexion.executescript(ESQUEMA)
    conexion.commit()


def obtener_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = conectar(current_app.config["RUTA_BD"])
    return g.db


def _cerrar_db(_error=None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def inicializar(app: Flask) -> None:
    with contextlib.closing(conectar(app.config["RUTA_BD"])) as conexion:
        crear_esquema(conexion)
    app.teardown_appcontext(_cerrar_db)
