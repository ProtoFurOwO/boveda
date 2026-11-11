"""Inspecciona la base de datos de Bóveda para una demostración.

Uso:
  python scripts/inspeccionar_bd.py
  python scripts/inspeccionar_bd.py usuarios
  python scripts/inspeccionar_bd.py mensajes --limite 10 --completo
  python scripts/inspeccionar_bd.py compartidos
  python scripts/inspeccionar_bd.py buscar "CLAVE-SECRETA-4321"
  python scripts/inspeccionar_bd.py esquema

La base por defecto es data/boveda.db. Si la app usa otra, define BOVEDA_BASE_DATOS.
Nunca muestra la clave maestra: esa no está en la base.
"""

import argparse
import contextlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from boveda.config import Configuracion, ruta_relativa  # noqa: E402
from boveda.db import conectar  # noqa: E402

RECORTE = 90


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspecciona la base de datos de Bóveda.")
    parser.add_argument(
        "accion",
        nargs="?",
        default="resumen",
        choices=["resumen", "usuarios", "mensajes", "compartidos", "buscar", "esquema"],
    )
    parser.add_argument("texto", nargs="?", help="Texto a buscar con la acción buscar")
    parser.add_argument("--limite", type=int, default=20)
    parser.add_argument("--completo", action="store_true", help="No recortar los valores largos")
    args = parser.parse_args()

    cfg = Configuracion.desde_entorno()
    if not cfg.ruta_bd.exists():
        print(f"No existe {ruta_relativa(cfg.ruta_bd)}. Arranca la app y crea una cuenta primero.")
        return 1

    with contextlib.closing(conectar(cfg.ruta_bd)) as db:
        if args.accion == "resumen":
            _resumen(db, cfg)
        elif args.accion == "usuarios":
            _usuarios(db, args)
        elif args.accion == "mensajes":
            _mensajes(db, args)
        elif args.accion == "compartidos":
            _compartidos(db, args)
        elif args.accion == "buscar":
            return _buscar(db, args.texto)
        elif args.accion == "esquema":
            _esquema(db)
    return 0


def _resumen(db, cfg) -> None:
    print(f"Base de datos: {ruta_relativa(cfg.ruta_bd)}")
    print(f"Usuarios:              {db.execute('SELECT COUNT(*) FROM usuarios').fetchone()[0]}")
    print(f"Mensajes:              {db.execute('SELECT COUNT(*) FROM mensajes').fetchone()[0]}")
    print(f"Enlaces compartidos:   {db.execute('SELECT COUNT(*) FROM compartidos').fetchone()[0]}")
    print("\nOpciones: usuarios, mensajes, compartidos, buscar <texto>, esquema")


def _usuarios(db, args) -> None:
    filas = db.execute(
        "SELECT id, nombre, hash_contrasena, sal_llave, clave_publica_pem, clave_privada_cifrada, creado_en "
        "FROM usuarios ORDER BY nombre LIMIT ?",
        (args.limite,),
    ).fetchall()
    for usuario in filas:
        print(f"\nUsuario: {usuario['nombre']}  ({usuario['id']})")
        print(f"  creado:               {usuario['creado_en']}")
        print(f"  hash de contraseña:   {_ver(usuario['hash_contrasena'], args)}")
        print(f"  sal de la llave:      {_ver(usuario['sal_llave'], args)}")
        print(f"  llave pública:        {usuario['clave_publica_pem'].strip()}")
        print(f"  llave privada cifrada: {_ver(usuario['clave_privada_cifrada'], args)}")
    print("\nLa contraseña no se guarda. El hash no se puede revertir; la llave privada solo se abre con la contraseña.")


def _mensajes(db, args) -> None:
    filas = db.execute(
        "SELECT m.*, r.nombre AS remitente, d.nombre AS destinatario "
        "FROM mensajes m JOIN usuarios r ON r.id = m.remitente_id JOIN usuarios d ON d.id = m.destinatario_id "
        "ORDER BY m.creado_en DESC LIMIT ?",
        (args.limite,),
    ).fetchall()
    for mensaje in filas:
        print(f"\nMensaje: {mensaje['id']}")
        print(f"  de:              {mensaje['remitente']} -> {mensaje['destinatario']}")
        print(f"  creado:          {mensaje['creado_en']}")
        print(f"  asunto cifrado:  {_ver(mensaje['asunto_cifrado'], args)}")
        print(f"  cuerpo cifrado:  {_ver(mensaje['cuerpo_cifrado'], args)}")
        print(f"  firma Ed25519:   {_ver(mensaje['firma'] or 'sin firma', args)}")
        print(f"  firmado:         {mensaje['firmado_en'] or 'sin firma'}")


def _compartidos(db, args) -> None:
    filas = db.execute(
        "SELECT c.*, u.nombre AS nombre_creador FROM compartidos c JOIN usuarios u ON u.id = c.creado_por "
        "ORDER BY c.creado_en DESC LIMIT ?",
        (args.limite,),
    ).fetchall()
    for enlace in filas:
        print(f"\nEnlace: {enlace['id']}")
        print(f"  mensaje:        {enlace['mensaje_id']}")
        print(f"  creado por:     {enlace['nombre_creador']}  ({enlace['creado_en']})")
        print(f"  expira:         {enlace['expira_en']}")
        print(f"  revocado:       {enlace['revocado_en'] or 'no'}")
        print(f"  hash del token: {_ver(enlace['token_hash'], args)}")
    print("\nEl token del enlace no se guarda: solo su hash SHA-256.")


def _buscar(db, texto: str | None) -> int:
    if not texto:
        print('Uso: python scripts/inspeccionar_bd.py buscar "CLAVE-SECRETA-4321"')
        return 2
    patron = f"%{texto}%"
    coincidencias = db.execute(
        "SELECT COUNT(*) FROM mensajes WHERE asunto_cifrado LIKE ? OR cuerpo_cifrado LIKE ?",
        (patron, patron),
    ).fetchone()[0]
    volcado = "\n".join(db.iterdump())
    print(f"Buscando {texto!r}...")
    print(f"Coincidencias en campos cifrados: {coincidencias}")
    print(f"Aparece en el volcado lógico de la base: {texto in volcado}")
    if texto not in volcado:
        print("No aparece en claro: el texto está cifrado en la base de datos.")
    else:
        print("Aparece: usa una marca única; puede coincidir por casualidad con base64.")
    return 0


def _esquema(db) -> None:
    for tabla in db.execute("SELECT name, sql FROM sqlite_master WHERE type = 'table' ORDER BY name"):
        print(f"\n-- {tabla['name']}\n{tabla['sql']}")


def _ver(valor, args, limite: int = RECORTE) -> str:
    if valor is None:
        return "—"
    texto = str(valor)
    if args.completo or len(texto) <= limite:
        return texto
    return f"{texto[:limite]}... ({len(texto)} caracteres)"


if __name__ == "__main__":
    sys.exit(main())
