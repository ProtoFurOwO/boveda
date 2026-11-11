"""Simula a un atacante sobre la base de datos REAL de Bóveda. Solo para demostración.

Modos:
  llave  El atacante tiene la clave maestra: cambia el cuerpo y lo vuelve a cifrar.
         AES-GCM no detecta el cambio, pero la firma Ed25519 sí.
  bytes  El atacante no tiene la clave: corrompe un byte del cifrado.
         AES-GCM lo detecta al descifrar.
  trasplantar  Copia el cuerpo cifrado de otro mensaje a este. El destino ya no
               se puede descifrar porque los datos asociados (AAD) no coinciden.

Uso:
  python scripts/manipular_mensaje.py <id_mensaje> llave ["nuevo texto"]
  python scripts/manipular_mensaje.py <id_mensaje> bytes
  python scripts/manipular_mensaje.py <id_destino> trasplantar <id_origen>
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from boveda import db as base_datos  # noqa: E402
from boveda.config import Configuracion  # noqa: E402
from boveda.criptografia import claves, simetrico  # noqa: E402
from boveda.servicios import mensajes  # noqa: E402

MODOS = ("llave", "bytes", "trasplantar")


def alterar_con_clave(db, clave_datos: bytes, mensaje_id: str, nuevo_cuerpo: str) -> str:
    fila = _buscar(db, mensaje_id)
    contexto = mensajes.contexto_mensaje(fila["remitente_id"], fila["destinatario_id"], mensaje_id, "cuerpo")
    original = simetrico.descifrar_texto(fila["cuerpo_cifrado"], clave_datos, contexto)
    db.execute(
        "UPDATE mensajes SET cuerpo_cifrado = ? WHERE id = ?",
        (simetrico.cifrar_texto(nuevo_cuerpo, clave_datos, contexto), mensaje_id),
    )
    db.commit()
    return original


def corromper_cifrado(db, mensaje_id: str) -> None:
    fila = _buscar(db, mensaje_id)
    prefijo, _, cuerpo = fila["cuerpo_cifrado"].rpartition(":")
    cambiado = ("B" if cuerpo[0] != "B" else "C") + cuerpo[1:]
    db.execute("UPDATE mensajes SET cuerpo_cifrado = ? WHERE id = ?", (f"{prefijo}:{cambiado}", mensaje_id))
    db.commit()


def trasplantar_cifrado(db, destino_id: str, origen_id: str) -> None:
    destino = _buscar(db, destino_id)
    origen = _buscar(db, origen_id)
    db.execute("UPDATE mensajes SET cuerpo_cifrado = ? WHERE id = ?", (origen["cuerpo_cifrado"], destino["id"]))
    db.commit()


def _buscar(db, mensaje_id: str):
    fila = db.execute("SELECT * FROM mensajes WHERE id = ?", (mensaje_id,)).fetchone()
    if fila is None:
        raise SystemExit(f"No existe ningún mensaje con id {mensaje_id}")
    return fila


def main(argv: list[str]) -> int:
    if len(argv) < 3 or argv[2] not in MODOS:
        print(__doc__)
        return 2
    mensaje_id, modo = argv[1], argv[2]

    cfg = Configuracion.desde_entorno()
    if not cfg.ruta_bd.exists():
        print("Todavía no hay base de datos. Envía un mensaje primero.")
        return 1
    if not cfg.clave_maestra_b64 and not cfg.ruta_clave.exists():
        print("No se encontró la clave maestra. Sin ella no hay forma de descifrar el mensaje.")
        return 1

    maestra = claves.cargar_clave_maestra(cfg.clave_maestra_b64, cfg.ruta_clave)
    clave_datos = claves.derivar_subclave(maestra.valor, "datos-mensajes")
    db = base_datos.conectar(cfg.ruta_bd)
    try:
        if modo == "llave":
            nuevo = argv[3] if len(argv) > 3 else "Mensaje alterado por un atacante."
            original = alterar_con_clave(db, clave_datos, mensaje_id, nuevo)
            print(f"Contenido original: {original!r}")
            print(f"Contenido ahora:    {nuevo!r}")
        elif modo == "bytes":
            corromper_cifrado(db, mensaje_id)
            print("Se corrompió un byte del cifrado en la base de datos.")
        else:
            if len(argv) < 4:
                print(__doc__)
                return 2
            trasplantar_cifrado(db, mensaje_id, argv[3])
            print(f"Se copió el cifrado del mensaje {argv[3]} al mensaje {mensaje_id}.")
            print("El destino ya no se puede descifrar; el mensaje original sigue válido.")
        print("Recarga la página del mensaje o el enlace compartido para ver el resultado.")
    finally:
        db.close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
