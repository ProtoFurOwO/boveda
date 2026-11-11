"""Mensajes entre usuarios.

Cifrado simétrico: asunto y cuerpo se cifran con AES-256-GCM antes de guardarse.
Firma asimétrica: al enviar, el remitente firma el mensaje con su llave privada Ed25519,
que solo se desbloquea con su contraseña. El destinatario verifica la firma con la clave
pública del remitente. Solo el remitente y el destinatario pueden abrir el mensaje.
"""

import base64
import uuid
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from boveda.criptografia import asimetrico, simetrico
from boveda.servicios import comprobantes, usuarios
from boveda.servicios.comun import ErrorServicio, NoEncontrado, ahora_iso

ASUNTO_MAX = 120
CUERPO_MAX = 20000

SIN_FIRMA = "sin_firmar"
VALIDA = "valida"
INVALIDA = "invalida"

BANDEJAS = ("recibidos", "enviados")

MOTIVO_ALTERADO = "Los datos cifrados no pasan la autenticación AES-GCM: fueron alterados o la clave maestra no coincide"

_CONSULTA = (
    "SELECT m.*, r.nombre AS remitente, d.nombre AS destinatario, r.clave_publica_pem "
    "FROM mensajes m "
    "JOIN usuarios r ON r.id = m.remitente_id "
    "JOIN usuarios d ON d.id = m.destinatario_id"
)


@dataclass(frozen=True)
class Mensaje:
    id: str
    asunto: str
    cuerpo: str
    remitente: str
    destinatario: str
    creado_en: str
    firmado_en: str | None
    firma: str | None
    estado_firma: str
    motivo_firma: str
    descifrable: bool
    huella: str
    asunto_cifrado: str
    cuerpo_cifrado: str
    clave_publica_pem: str


def contexto_mensaje(remitente_id: str, destinatario_id: str, mensaje_id: str, campo: str) -> bytes:
    """Datos asociados (AAD): atan cada cifrado a su remitente, destinatario, mensaje y campo."""
    return f"mensaje|{remitente_id}|{destinatario_id}|{mensaje_id}|{campo}".encode("utf-8")


def listar(db, clave: bytes, usuario_id: str, bandeja: str) -> list[Mensaje]:
    if bandeja == "enviados":
        filas = db.execute(_CONSULTA + " WHERE m.remitente_id = ? ORDER BY m.creado_en DESC", (usuario_id,)).fetchall()
    else:
        filas = db.execute(_CONSULTA + " WHERE m.destinatario_id = ? ORDER BY m.creado_en DESC", (usuario_id,)).fetchall()
    return [_leer(clave, fila) for fila in filas]


def obtener(db, clave: bytes, usuario_id: str, mensaje_id: str) -> Mensaje:
    fila = db.execute(
        _CONSULTA + " WHERE m.id = ? AND (m.remitente_id = ? OR m.destinatario_id = ?)",
        (mensaje_id, usuario_id, usuario_id),
    ).fetchone()
    if fila is None:
        raise NoEncontrado("El mensaje no existe")
    return _leer(clave, fila)


def enviar(
    db, clave: bytes, remitente_id: str, destinatario_nombre: str, asunto: str, cuerpo: str, contrasena: str
) -> str:
    asunto, cuerpo = _validar(asunto, cuerpo)
    if not contrasena:
        raise ErrorServicio("Escribe tu contraseña para firmar el mensaje")
    destinatario = usuarios.buscar_por_nombre(db, destinatario_nombre or "")
    if destinatario is None:
        raise ErrorServicio("Ese destinatario no existe")
    if destinatario["id"] == remitente_id:
        raise ErrorServicio("No puedes enviarte un mensaje a ti mismo")
    remitente = usuarios.buscar_por_id(db, remitente_id)

    llave = usuarios.desbloquear_llave_firma(remitente, contrasena)
    mensaje_id = uuid.uuid4().hex
    asunto_cifrado, cuerpo_cifrado = _cifrar(clave, remitente_id, destinatario["id"], mensaje_id, asunto, cuerpo)
    creado_en = ahora_iso()
    payload = comprobantes.construir_payload(
        mensaje_id, remitente["nombre"], destinatario["nombre"], asunto, cuerpo, creado_en, creado_en
    )
    firma = base64.b64encode(asimetrico.firmar(llave, comprobantes.mensaje_firmado(payload))).decode("ascii")
    db.execute(
        "INSERT INTO mensajes (id, remitente_id, destinatario_id, asunto_cifrado, cuerpo_cifrado, creado_en, firma, firmado_en) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (mensaje_id, remitente_id, destinatario["id"], asunto_cifrado, cuerpo_cifrado, creado_en, firma, creado_en),
    )
    db.commit()
    return mensaje_id


def eliminar(db, usuario_id: str, mensaje_id: str) -> None:
    fila = db.execute(
        "SELECT id FROM mensajes WHERE id = ? AND (remitente_id = ? OR destinatario_id = ?)",
        (mensaje_id, usuario_id, usuario_id),
    ).fetchone()
    if fila is None:
        raise NoEncontrado("El mensaje no existe")
    db.execute("DELETE FROM mensajes WHERE id = ?", (mensaje_id,))
    db.commit()


def comprobante(db, clave: bytes, usuario_id: str, mensaje_id: str) -> dict:
    msg = obtener(db, clave, usuario_id, mensaje_id)
    if msg.estado_firma == SIN_FIRMA:
        raise ErrorServicio("Este mensaje no tiene firma")
    if msg.estado_firma == INVALIDA:
        raise ErrorServicio("No se emite comprobante: la firma de este mensaje ya no es válida")
    payload = comprobantes.construir_payload(
        msg.id, msg.remitente, msg.destinatario, msg.asunto, msg.cuerpo, msg.creado_en, msg.firmado_en
    )
    return comprobantes.emitir(payload, msg.firma, msg.clave_publica_pem)


def _leer(clave: bytes, fila) -> Mensaje:
    clave_publica = asimetrico.cargar_publica(fila["clave_publica_pem"])
    comunes = dict(
        id=fila["id"],
        remitente=fila["remitente"],
        destinatario=fila["destinatario"],
        creado_en=fila["creado_en"],
        firmado_en=fila["firmado_en"],
        firma=fila["firma"],
        huella=asimetrico.huella(clave_publica),
        asunto_cifrado=fila["asunto_cifrado"],
        cuerpo_cifrado=fila["cuerpo_cifrado"],
        clave_publica_pem=fila["clave_publica_pem"],
    )
    asunto = _descifrar_campo(clave, fila, "asunto")
    cuerpo = _descifrar_campo(clave, fila, "cuerpo")
    if asunto is None or cuerpo is None:
        return Mensaje(
            **comunes,
            asunto=asunto if asunto is not None else "[asunto no disponible]",
            cuerpo="",
            estado_firma=INVALIDA,
            motivo_firma=MOTIVO_ALTERADO,
            descifrable=False,
        )
    estado, motivo = _estado_firma(fila, clave_publica, asunto, cuerpo)
    return Mensaje(
        **comunes,
        asunto=asunto,
        cuerpo=cuerpo,
        estado_firma=estado,
        motivo_firma=motivo,
        descifrable=True,
    )


def _estado_firma(fila, clave_publica: Ed25519PublicKey, asunto: str, cuerpo: str) -> tuple[str, str]:
    if not fila["firma"]:
        return SIN_FIRMA, "Este mensaje no tiene firma"
    payload = comprobantes.construir_payload(
        fila["id"], fila["remitente"], fila["destinatario"], asunto, cuerpo, fila["creado_en"], fila["firmado_en"]
    )
    firma = base64.b64decode(fila["firma"])
    if asimetrico.verificar(clave_publica, firma, comprobantes.mensaje_firmado(payload)):
        return VALIDA, "Firma verificada: el mensaje es de quien dice y no cambió desde que se envió"
    return INVALIDA, "El contenido o los datos del mensaje no coinciden con la firma: fue alterado"


def _cifrar(
    clave: bytes, remitente_id: str, destinatario_id: str, mensaje_id: str, asunto: str, cuerpo: str
) -> tuple[str, str]:
    return (
        simetrico.cifrar_texto(asunto, clave, contexto_mensaje(remitente_id, destinatario_id, mensaje_id, "asunto")),
        simetrico.cifrar_texto(cuerpo, clave, contexto_mensaje(remitente_id, destinatario_id, mensaje_id, "cuerpo")),
    )


def _descifrar_campo(clave: bytes, fila, campo: str) -> str | None:
    contexto = contexto_mensaje(fila["remitente_id"], fila["destinatario_id"], fila["id"], campo)
    try:
        return simetrico.descifrar_texto(fila[f"{campo}_cifrado"], clave, contexto)
    except simetrico.ErrorCifrado:
        return None


def _validar(asunto: str, cuerpo: str) -> tuple[str, str]:
    asunto = (asunto or "").strip()
    cuerpo = (cuerpo or "").replace("\r\n", "\n")
    if not asunto:
        raise ErrorServicio("El asunto es obligatorio")
    if len(asunto) > ASUNTO_MAX:
        raise ErrorServicio(f"El asunto no puede superar {ASUNTO_MAX} caracteres")
    if not cuerpo.strip():
        raise ErrorServicio("El mensaje no puede estar vacío")
    if len(cuerpo) > CUERPO_MAX:
        raise ErrorServicio(f"El mensaje no puede superar {CUERPO_MAX} caracteres")
    return asunto, cuerpo
