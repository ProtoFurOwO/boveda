"""Demostración del flujo completo en consola: dos usuarios se envían un mensaje firmado.

Usa una base de datos y una clave maestra temporales: no toca tus mensajes reales.

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
from boveda.servicios import compartidos, comprobantes, mensajes, usuarios  # noqa: E402
from boveda.servicios.comun import NoEncontrado  # noqa: E402
from manipular_mensaje import alterar_con_clave, corromper_cifrado, trasplantar_cifrado  # noqa: E402

CONTRASENA_ANA = "contraseña-de-ana-2026"
CONTRASENA_BETO = "contraseña-de-beto-2026"
CONTRASENA_CARLA = "contraseña-de-carla-2026"


def seccion(texto: str) -> None:
    print(f"\n{texto}")
    print("-" * len(texto))


def main() -> None:
    carpeta = Path(tempfile.mkdtemp(prefix="boveda-demo-"))
    clave_datos = claves.derivar_subclave(secrets.token_bytes(32), "datos-mensajes")

    with contextlib.closing(base_datos.conectar(carpeta / "demo.db")) as db:
        base_datos.crear_esquema(db)

        seccion("1. Dos cuentas, cada una con su par de llaves")
        ana = usuarios.registrar(db, "ana", CONTRASENA_ANA)
        beto = usuarios.registrar(db, "beto", CONTRASENA_BETO)
        fila_ana = usuarios.buscar_por_id(db, ana)
        print("Llave pública de ana (se puede compartir):")
        print(fila_ana["clave_publica_pem"].strip())
        print("Llave privada de ana en la base de datos:", fila_ana["clave_privada_cifrada"][:40] + "...")

        seccion("2. Ana envía un mensaje firmado a Beto")
        mensaje_id = mensajes.enviar(
            db,
            clave_datos,
            ana,
            "beto",
            "Clave de la reunión",
            "La clave de la sala es 4321.\nNos vemos a las 10.",
            CONTRASENA_ANA,
        )
        fila = db.execute("SELECT asunto_cifrado, cuerpo_cifrado FROM mensajes WHERE id = ?", (mensaje_id,)).fetchone()
        print("Entra en claro:    ", "La clave de la sala es 4321.")
        print("Se guarda cifrado: ", fila["cuerpo_cifrado"][:60] + "...")
        print("El texto aparece en la base de datos:", "4321" in fila["cuerpo_cifrado"])

        seccion("3. Beto lo lee: se descifra y se verifica la firma")
        msg = mensajes.obtener(db, clave_datos, beto, mensaje_id)
        print("Asunto:", msg.asunto)
        print("Cuerpo:", msg.cuerpo.replace("\n", " / "))
        print("Estado:", msg.estado_firma, "-", msg.motivo_firma)
        print("Huella de la llave de ana:", msg.huella)

        seccion("4. Un usuario ajeno no puede abrirlo")
        carla = usuarios.registrar(db, "carla", CONTRASENA_CARLA)
        try:
            mensajes.obtener(db, clave_datos, carla, mensaje_id)
        except NoEncontrado:
            print("Carla pidió el mensaje y recibió: no existe.")

        seccion("5. Atacante con la clave maestra cambia el cuerpo")
        alterar_con_clave(db, clave_datos, mensaje_id, "La clave de la sala es 0000.")
        msg = mensajes.obtener(db, clave_datos, beto, mensaje_id)
        print("El cifrado es válido, porque lo produjo la clave maestra.")
        print("Estado:", msg.estado_firma, "-", msg.motivo_firma)

        seccion("6. Comprobante verificable sin la aplicación")
        segundo = mensajes.enviar(
            db, clave_datos, ana, "beto", "Confirmación", "Confirmo la reunión del viernes.", CONTRASENA_ANA
        )
        comprobante = mensajes.comprobante(db, clave_datos, beto, segundo)
        clave_publica = asimetrico.cargar_publica(comprobante["clave_publica_pem"])
        print("Comprobante original:", comprobantes.validar(comprobante, clave_publica).mensaje)
        comprobante["payload"]["cuerpo"] = "Cancelo la reunión."
        print("Comprobante editado: ", comprobantes.validar(comprobante, clave_publica).mensaje)

        seccion("7. Enlace público de solo lectura")
        enlace = compartidos.crear_enlace(db, segundo, beto)
        publico = compartidos.resolver_enlace(db, clave_datos, enlace.token)
        print("Enlace: /p/" + enlace.token)
        print("El enlace lee:", publico.mensaje.cuerpo)
        print("Estado:", publico.mensaje.estado_firma)
        print("Compartido por:", publico.creado_por)

        seccion("8. Alguien con la clave maestra altera el mensaje compartido")
        alterar_con_clave(db, clave_datos, segundo, "Cancelo la reunión.")
        publico = compartidos.resolver_enlace(db, clave_datos, enlace.token)
        print("El enlace sigue abriendo, pero muestra:", publico.mensaje.estado_firma)
        print("Cuerpo:", publico.mensaje.cuerpo)
        print("Motivo:", publico.mensaje.motivo_firma)

        seccion("9. Revocar el enlace")
        compartidos.revocar_enlace(db, segundo, enlace.id, beto)
        try:
            compartidos.resolver_enlace(db, clave_datos, enlace.token)
        except NoEncontrado:
            print("Después de revocarlo, el enlace ya no existe.")

        seccion("10. Mover el cifrado de un mensaje a otro")
        origen = mensajes.enviar(db, clave_datos, ana, "beto", "Origen", "Texto del origen", CONTRASENA_ANA)
        destino = mensajes.enviar(db, clave_datos, ana, "beto", "Destino", "Texto del destino", CONTRASENA_ANA)
        trasplantar_cifrado(db, destino, origen)
        msg_destino = mensajes.obtener(db, clave_datos, beto, destino)
        msg_origen = mensajes.obtener(db, clave_datos, beto, origen)
        print("El destino se puede descifrar:", msg_destino.descifrable)
        print("Estado del destino:", msg_destino.estado_firma)
        print("El origen sigue válido:", msg_origen.estado_firma, "-", msg_origen.cuerpo)

        seccion("11. Atacante sin la clave maestra corrompe el cifrado")
        cuarto = mensajes.enviar(db, clave_datos, ana, "beto", "Otro", "Otro texto", CONTRASENA_ANA)
        corromper_cifrado(db, cuarto)
        msg = mensajes.obtener(db, clave_datos, beto, cuarto)
        print("Estado:", msg.estado_firma, "-", msg.motivo_firma)

    print(f"\nBase temporal de la demostración: {carpeta}")


if __name__ == "__main__":
    main()
