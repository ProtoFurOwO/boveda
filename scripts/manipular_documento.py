"""Simula a un atacante sobre la base de datos REAL de Bóveda. Solo para demostración.

Modos:
  llave  El atacante tiene la clave maestra: cambia el texto y lo vuelve a cifrar.
         AES-GCM no detecta el cambio, pero la firma Ed25519 sí.
  bytes  El atacante no tiene la clave: corrompe un byte del cifrado.
         AES-GCM lo detecta al descifrar.

Uso:
  python scripts/manipular_documento.py <id_documento> llave ["nuevo texto"]
  python scripts/manipular_documento.py <id_documento> bytes
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from boveda import db as base_datos  # noqa: E402
from boveda.config import Configuracion  # noqa: E402
from boveda.criptografia import claves, simetrico  # noqa: E402
from boveda.servicios import documentos  # noqa: E402

MODOS = ("llave", "bytes")


def alterar_con_clave(db, clave_datos: bytes, documento_id: str, nuevo_contenido: str) -> str:
    fila = _buscar(db, documento_id)
    contexto = documentos.contexto_documento(fila["usuario_id"], documento_id, "contenido")
    original = simetrico.descifrar_texto(fila["contenido_cifrado"], clave_datos, contexto)
    db.execute(
        "UPDATE documentos SET contenido_cifrado = ? WHERE id = ?",
        (simetrico.cifrar_texto(nuevo_contenido, clave_datos, contexto), documento_id),
    )
    db.commit()
    return original


def corromper_cifrado(db, documento_id: str) -> None:
    fila = _buscar(db, documento_id)
    prefijo, _, cuerpo = fila["contenido_cifrado"].rpartition(":")
    cambiado = ("B" if cuerpo[0] != "B" else "C") + cuerpo[1:]
    db.execute("UPDATE documentos SET contenido_cifrado = ? WHERE id = ?", (f"{prefijo}:{cambiado}", documento_id))
    db.commit()


def _buscar(db, documento_id: str):
    fila = db.execute("SELECT * FROM documentos WHERE id = ?", (documento_id,)).fetchone()
    if fila is None:
        raise SystemExit(f"No existe ningún documento con id {documento_id}")
    return fila


def main(argv: list[str]) -> int:
    if len(argv) < 3 or argv[2] not in MODOS:
        print(__doc__)
        return 2
    documento_id, modo = argv[1], argv[2]

    cfg = Configuracion.desde_entorno()
    if not cfg.ruta_bd.exists():
        print("Todavía no hay base de datos. Crea un documento primero.")
        return 1
    if not cfg.clave_maestra_b64 and not cfg.ruta_clave.exists():
        print("No se encontró la clave maestra. Sin ella no hay forma de descifrar el documento.")
        return 1

    maestra = claves.cargar_clave_maestra(cfg.clave_maestra_b64, cfg.ruta_clave)
    clave_datos = claves.derivar_subclave(maestra.valor, "datos-documentos")
    db = base_datos.conectar(cfg.ruta_bd)
    try:
        if modo == "llave":
            nuevo = argv[3] if len(argv) > 3 else "Texto alterado por un atacante."
            original = alterar_con_clave(db, clave_datos, documento_id, nuevo)
            print(f"Contenido original: {original!r}")
            print(f"Contenido ahora:    {nuevo!r}")
        else:
            corromper_cifrado(db, documento_id)
            print("Se corrompió un byte del cifrado en la base de datos.")
        print("Recarga la página del documento para ver el resultado.")
    finally:
        db.close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
