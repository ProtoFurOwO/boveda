import base64
import secrets

import pytest

from boveda import db as base_datos
from boveda.app import crear_app
from boveda.config import Configuracion
from boveda.criptografia import claves, contrasenas


@pytest.fixture(autouse=True)
def scrypt_rapido(monkeypatch):
    """Con N de producción scrypt tarda ~0.4 s por operación; las pruebas usan N bajo."""
    monkeypatch.setattr(contrasenas, "N", 2**10)


@pytest.fixture
def clave_datos():
    return claves.derivar_subclave(secrets.token_bytes(32), "datos-mensajes")


@pytest.fixture
def db(tmp_path):
    conexion = base_datos.conectar(tmp_path / "prueba.db")
    base_datos.crear_esquema(conexion)
    yield conexion
    conexion.close()


@pytest.fixture
def app(tmp_path):
    cfg = Configuracion(
        ruta_bd=tmp_path / "boveda.db",
        clave_maestra_b64=base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
        ruta_clave=tmp_path / "clave_maestra.key",
    )
    aplicacion = crear_app(cfg)
    aplicacion.config["TESTING"] = True
    return aplicacion


@pytest.fixture
def cliente(app):
    return app.test_client()
