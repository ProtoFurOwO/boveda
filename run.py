"""Arranca Bóveda con waitress, un servidor WSGI de producción que funciona en Windows, Linux y macOS.

Uso:  python run.py
"""

import logging

from waitress import serve

from boveda.app import crear_app
from boveda.config import Configuracion


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
    cfg = Configuracion.desde_entorno()
    app = crear_app(cfg)
    print(f"Bóveda lista en http://{cfg.host}:{cfg.puerto}")
    print(f"Clave maestra: {app.config['CLAVE_ORIGEN']}")
    print("Detén el servidor con Ctrl+C.")
    serve(app, host=cfg.host, port=cfg.puerto, threads=8)


if __name__ == "__main__":
    main()
