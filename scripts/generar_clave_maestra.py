r"""Imprime una clave maestra nueva (256 bits en base64) para la variable BOVEDA_CLAVE_MAESTRA.

PowerShell:
  $env:BOVEDA_CLAVE_MAESTRA = python scripts\generar_clave_maestra.py

Guarda el valor en el gestor de secretos de tu servidor. No lo pegues en el código
ni en un archivo que subas a Git.
"""

import base64
import secrets

print(base64.b64encode(secrets.token_bytes(32)).decode("ascii"))
