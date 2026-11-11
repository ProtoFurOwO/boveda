"""Verifica un certificado de Bóveda sin la aplicación ni la base de datos.

Uso:
  python scripts/verificar_certificado.py certificado.json
  python scripts/verificar_certificado.py certificado.json --clave-publica clave_autor.pem

Sin --clave-publica solo se comprueba que la firma coincide con la clave que trae el propio
certificado. Eso prueba integridad, pero no quién firmó. Para autenticidad, compara con la
clave pública del autor que obtengas por una fuente de confianza.
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from boveda.criptografia import asimetrico  # noqa: E402
from boveda.servicios import certificados  # noqa: E402
from boveda.servicios.comun import ErrorServicio  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verifica un certificado de Bóveda.")
    parser.add_argument("certificado", type=Path, help="Archivo .json descargado desde la aplicación")
    parser.add_argument("--clave-publica", type=Path, help="PEM de la clave pública del autor (fuente de confianza)")
    args = parser.parse_args(argv)

    try:
        certificado = json.loads(args.certificado.read_text(encoding="utf-8"))
        if args.clave_publica:
            clave = asimetrico.cargar_publica(args.clave_publica.read_text(encoding="ascii"))
        else:
            print("Aviso: sin clave de confianza. Solo se comprueba la integridad, no la autoría.")
            clave = asimetrico.cargar_publica(certificado["clave_publica_pem"])
        resultado = certificados.validar(certificado, clave)
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError, ErrorServicio) as e:
        print(f"No se pudo leer el certificado: {e}")
        return 2

    marca = "OK" if resultado.valido else "FALLO"
    print(f"[{marca}] {resultado.mensaje}")
    print(f"Documento: {resultado.payload['titulo']}")
    print(f"Autor:     {resultado.payload['autor']}")
    print(f"Firmado:   {resultado.payload['firmado_en']}")
    return 0 if resultado.valido else 1


if __name__ == "__main__":
    sys.exit(main())
