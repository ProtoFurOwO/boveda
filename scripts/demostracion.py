"""Demostración del flujo completo en consola.

Usa una base de datos y una clave maestra temporales: no toca tus documentos reales.

Uso:  python scripts/demostracion.py
"""

import contextlib
import secrets
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from boveda import db as base_datos  # noqa: E402
from boveda.criptografia import asimetrico, claves  # noqa: E402
from boveda.servicios import certificados, documentos, usuarios  # noqa: E402
from manipular_documento import alterar_con_clave, corromper_cifrado  # noqa: E402

CONTRASENA = "contraseña-de-demo-2026"


def seccion(texto: str) -> None:
    print(f"\n{texto}")
    print("-" * len(texto))


def main() -> None:
    carpeta = Path(tempfile.mkdtemp(prefix="boveda-demo-"))
    clave_datos = claves.derivar_subclave(secrets.token_bytes(32), "datos-documentos")

    with contextlib.closing(base_datos.conectar(carpeta / "demo.db")) as db:
        base_datos.crear_esquema(db)

        seccion("1. Alta: la llave privada de firma queda cifrada con tu contraseña")
        uid = usuarios.registrar(db, "demo", CONTRASENA)
        usuario = usuarios.buscar_por_id(db, uid)
        print("Llave pública (se puede compartir):")
        print(usuario["clave_publica_pem"].strip())
        print("Llave privada en la base de datos:", usuario["clave_privada_cifrada"][:40] + "...")

        seccion("2. Entrada en claro -> AES-256-GCM -> base de datos")
        titulo_entrada = "Clave del banco"
        contenido_entrada = "Usuario: ana.lopez\nNIP: 4321"
        doc_id = documentos.crear(db, clave_datos, uid, titulo_entrada, contenido_entrada)
        fila = db.execute("SELECT titulo_cifrado, contenido_cifrado FROM documentos WHERE id = ?", (doc_id,)).fetchone()
        print("Entra en claro:    ", titulo_entrada)
        print("Se guarda cifrado: ", fila["titulo_cifrado"][:60] + "...")
        print("El NIP aparece en la base de datos:", "4321" in fila["contenido_cifrado"])

        seccion("3. Lectura -> descifrado")
        doc = documentos.obtener(db, clave_datos, uid, doc_id)
        print("Se lee:", doc.titulo)
        print("Coincide con lo que entró:", (doc.titulo, doc.contenido) == (titulo_entrada, contenido_entrada))

        seccion("4. Firma digital Ed25519 con tu contraseña")
        documentos.firmar(db, clave_datos, uid, doc_id, CONTRASENA)
        doc = documentos.obtener(db, clave_datos, uid, doc_id)
        print("Estado:", doc.estado_firma, "-", doc.motivo_firma)
        print("Huella de la clave:", doc.huella)

        seccion("5. Atacante con la clave maestra cambia el texto")
        alterar_con_clave(db, clave_datos, doc_id, "Usuario: ana.lopez\nNIP: 0000")
        doc = documentos.obtener(db, clave_datos, uid, doc_id)
        print("El cifrado es válido, porque lo produjo la clave maestra.")
        print("Estado:", doc.estado_firma, "-", doc.motivo_firma)

        seccion("6. Certificado verificable sin la aplicación")
        doc_2 = documentos.crear(db, clave_datos, uid, "Contrato de servicios", "Pago mensual: 1,500 pesos")
        documentos.firmar(db, clave_datos, uid, doc_2, CONTRASENA)
        certificado = documentos.certificado(db, clave_datos, uid, doc_2)
        clave_publica = asimetrico.cargar_publica(certificado["clave_publica_pem"])
        print("Certificado original:", certificados.validar(certificado, clave_publica).mensaje)
        certificado["payload"]["contenido"] = "Pago mensual: 15,000 pesos"
        print("Certificado editado: ", certificados.validar(certificado, clave_publica).mensaje)

        seccion("7. Atacante sin la clave maestra corrompe el cifrado")
        corromper_cifrado(db, doc_2)
        doc = documentos.obtener(db, clave_datos, uid, doc_2)
        print("Estado:", doc.estado_firma, "-", doc.motivo_firma)

    print(f"\nBase temporal de la demostración: {carpeta}")


if __name__ == "__main__":
    main()
