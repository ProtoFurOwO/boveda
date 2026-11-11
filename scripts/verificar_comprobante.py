"""Verifica un comprobante de Bóveda sin la aplicación ni la base de datos.

Uso:
  python scripts/verificar_comprobante.py comprobante.json
  python scripts/verificar_comprobante.py comprobante.json --clave-publica clave_remitente.pem

Sin --clave-publica solo se comprueba que la firma coincide con la clave que trae el propio
comprobante. Eso prueba integridad, pero no quién lo envió. Para autenticidad, compara con la
clave pública del remitente que obtengas por una fuente de confianza.
"""

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from boveda.criptografia import asimetrico  # noqa: E402
from boveda.servicios import comprobantes  # noqa: E402
from boveda.servicios.comun import ErrorServicio  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verifica un comprobante de Bóveda.")
    parser.add_argument("comprobante", type=Path, help="Archivo .json descargado desde la aplicación")
    parser.add_argument("--clave-publica", type=Path, help="PEM de la clave pública del remitente (fuente de confianza)")
    args = parser.parse_args(argv)

    try:
        comprobante = json.loads(args.comprobante.read_text(encoding="utf-8"))
        if args.clave_publica:
            clave = asimetrico.cargar_publica(args.clave_publica.read_text(encoding="ascii"))
        else:
            print("Aviso: sin clave de confianza. Solo se comprueba la integridad, no la autoría.")
            clave = asimetrico.cargar_publica(comprobante["clave_publica_pem"])
        resultado = comprobantes.validar(comprobante, clave)
    except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError, ErrorServicio) as e:
        print(f"No se pudo leer el comprobante: {e}")
        return 2

    marca = "OK" if resultado.valido else "FALLO"
    print(f"[{marca}] {resultado.mensaje}")
    print(f"Asunto:    {resultado.payload['asunto']}")
    print(f"De:        {resultado.payload['remitente']}")
    print(f"Para:      {resultado.payload['destinatario']}")
    print(f"Firmado:   {resultado.payload['firmado_en']}")
    return 0 if resultado.valido else 1


if __name__ == "__main__":
    sys.exit(main())
