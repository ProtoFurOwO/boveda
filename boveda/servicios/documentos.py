"""Documentos del usuario.

Cifrado simétrico: título y contenido se cifran con AES-256-GCM antes de guardarse.
Firma asimétrica: el documento se firma con Ed25519 usando la llave privada del autor,
que solo se desbloquea al confirmar su contraseña. Cualquiera puede verificar la firma
con la clave pública registrada, sin contraseña.
"""

import base64
import uuid
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from boveda.criptografia import asimetrico, simetrico
from boveda.servicios import certificados, usuarios
from boveda.servicios.comun import ErrorServicio, NoEncontrado, ahora_iso

TITULO_MAX = 120
CONTENIDO_MAX = 20000

SIN_FIRMA = "sin_firmar"
VALIDA = "valida"
INVALIDA = "invalida"

MOTIVO_ALTERADO = "Los datos cifrados no pasan la autenticación AES-GCM: fueron alterados o la clave maestra no coincide"
MENSAJE_ALTERADO = "Los datos de este documento fueron alterados y no se pueden leer: elimínalo o restáuralo"

_CONSULTA = (
    "SELECT d.*, u.nombre AS autor, u.clave_publica_pem "
    "FROM documentos d JOIN usuarios u ON u.id = d.usuario_id"
)


@dataclass(frozen=True)
class Documento:
    id: str
    titulo: str
    contenido: str
    autor: str
    creado_en: str
    actualizado_en: str
    firmado_en: str | None
    firma: str | None
    estado_firma: str
    motivo_firma: str
    descifrable: bool
    huella: str
    titulo_cifrado: str
    contenido_cifrado: str
    clave_publica_pem: str


def contexto_documento(usuario_id: str, documento_id: str, campo: str) -> bytes:
    """Datos asociados (AAD): atan cada cifrado a su usuario, documento y campo."""
    return f"documento|{usuario_id}|{documento_id}|{campo}".encode("utf-8")


def listar(db, clave: bytes, usuario_id: str) -> list[Documento]:
    filas = db.execute(_CONSULTA + " WHERE d.usuario_id = ? ORDER BY d.actualizado_en DESC", (usuario_id,)).fetchall()
    return [_leer(clave, fila) for fila in filas]


def obtener(db, clave: bytes, usuario_id: str, documento_id: str) -> Documento:
    return _leer(clave, _fila(db, usuario_id, documento_id))


def crear(db, clave: bytes, usuario_id: str, titulo: str, contenido: str) -> str:
    titulo, contenido = _validar(titulo, contenido)
    documento_id = uuid.uuid4().hex
    titulo_cifrado, contenido_cifrado = _cifrar(clave, usuario_id, documento_id, titulo, contenido)
    ahora = ahora_iso()
    db.execute(
        "INSERT INTO documentos (id, usuario_id, titulo_cifrado, contenido_cifrado, creado_en, actualizado_en) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (documento_id, usuario_id, titulo_cifrado, contenido_cifrado, ahora, ahora),
    )
    db.commit()
    return documento_id


def actualizar(db, clave: bytes, usuario_id: str, documento_id: str, titulo: str, contenido: str) -> bool:
    """Devuelve False si no hubo cambios. Cualquier cambio invalida la firma anterior."""
    titulo, contenido = _validar(titulo, contenido)
    fila = _fila(db, usuario_id, documento_id)
    try:
        actual = _descifrar(clave, fila)
    except simetrico.ErrorCifrado as e:
        raise ErrorServicio(MENSAJE_ALTERADO) from e
    if actual == (titulo, contenido):
        return False
    titulo_cifrado, contenido_cifrado = _cifrar(clave, usuario_id, documento_id, titulo, contenido)
    db.execute(
        "UPDATE documentos SET titulo_cifrado = ?, contenido_cifrado = ?, actualizado_en = ?, "
        "firma = NULL, firmado_en = NULL WHERE id = ?",
        (titulo_cifrado, contenido_cifrado, ahora_iso(), documento_id),
    )
    db.commit()
    return True


def eliminar(db, usuario_id: str, documento_id: str) -> None:
    _fila(db, usuario_id, documento_id)
    db.execute("DELETE FROM documentos WHERE id = ? AND usuario_id = ?", (documento_id, usuario_id))
    db.commit()


def firmar(db, clave: bytes, usuario_id: str, documento_id: str, contrasena: str) -> None:
    if not contrasena:
        raise ErrorServicio("Escribe tu contraseña para firmar")
    fila = _fila(db, usuario_id, documento_id)
    try:
        titulo, contenido = _descifrar(clave, fila)
    except simetrico.ErrorCifrado as e:
        raise ErrorServicio(MENSAJE_ALTERADO) from e
    autor = usuarios.buscar_por_id(db, usuario_id)
    llave = usuarios.desbloquear_llave_firma(autor, contrasena)
    firmado_en = ahora_iso()
    payload = certificados.construir_payload(documento_id, autor["nombre"], titulo, contenido, fila["creado_en"], firmado_en)
    firma = asimetrico.firmar(llave, certificados.mensaje_firmado(payload))
    db.execute(
        "UPDATE documentos SET firma = ?, firmado_en = ? WHERE id = ?",
        (base64.b64encode(firma).decode("ascii"), firmado_en, documento_id),
    )
    db.commit()


def certificado(db, clave: bytes, usuario_id: str, documento_id: str) -> dict:
    doc = obtener(db, clave, usuario_id, documento_id)
    if doc.estado_firma == SIN_FIRMA:
        raise ErrorServicio("Firma el documento antes de descargar su certificado")
    if doc.estado_firma == INVALIDA:
        raise ErrorServicio("No se emite certificado: la firma de este documento ya no es válida")
    payload = certificados.construir_payload(doc.id, doc.autor, doc.titulo, doc.contenido, doc.creado_en, doc.firmado_en)
    return certificados.emitir(payload, doc.firma, doc.clave_publica_pem)


def _leer(clave: bytes, fila) -> Documento:
    clave_publica = asimetrico.cargar_publica(fila["clave_publica_pem"])
    comunes = dict(
        id=fila["id"],
        autor=fila["autor"],
        creado_en=fila["creado_en"],
        actualizado_en=fila["actualizado_en"],
        firmado_en=fila["firmado_en"],
        firma=fila["firma"],
        huella=asimetrico.huella(clave_publica),
        titulo_cifrado=fila["titulo_cifrado"],
        contenido_cifrado=fila["contenido_cifrado"],
        clave_publica_pem=fila["clave_publica_pem"],
    )
    titulo = _descifrar_campo(clave, fila, "titulo")
    contenido = _descifrar_campo(clave, fila, "contenido")
    if titulo is None or contenido is None:
        return Documento(
            **comunes,
            titulo=titulo if titulo is not None else "[título no disponible]",
            contenido="",
            estado_firma=INVALIDA,
            motivo_firma=MOTIVO_ALTERADO,
            descifrable=False,
        )
    estado, motivo = _estado_firma(fila, clave_publica, titulo, contenido)
    return Documento(
        **comunes,
        titulo=titulo,
        contenido=contenido,
        estado_firma=estado,
        motivo_firma=motivo,
        descifrable=True,
    )


def _estado_firma(fila, clave_publica: Ed25519PublicKey, titulo: str, contenido: str) -> tuple[str, str]:
    if not fila["firma"]:
        return SIN_FIRMA, "Aún no está firmado"
    payload = certificados.construir_payload(fila["id"], fila["autor"], titulo, contenido, fila["creado_en"], fila["firmado_en"])
    firma = base64.b64decode(fila["firma"])
    if asimetrico.verificar(clave_publica, firma, certificados.mensaje_firmado(payload)):
        return VALIDA, "El contenido coincide exactamente con lo firmado"
    return INVALIDA, "El contenido o sus metadatos no coinciden con lo firmado: el documento fue alterado"


def _fila(db, usuario_id: str, documento_id: str):
    fila = db.execute(_CONSULTA + " WHERE d.id = ? AND d.usuario_id = ?", (documento_id, usuario_id)).fetchone()
    if fila is None:
        raise NoEncontrado("El documento no existe")
    return fila


def _cifrar(clave: bytes, usuario_id: str, documento_id: str, titulo: str, contenido: str) -> tuple[str, str]:
    return (
        simetrico.cifrar_texto(titulo, clave, contexto_documento(usuario_id, documento_id, "titulo")),
        simetrico.cifrar_texto(contenido, clave, contexto_documento(usuario_id, documento_id, "contenido")),
    )


def _descifrar(clave: bytes, fila) -> tuple[str, str]:
    titulo = _descifrar_campo(clave, fila, "titulo")
    contenido = _descifrar_campo(clave, fila, "contenido")
    if titulo is None or contenido is None:
        raise simetrico.ErrorCifrado("El documento fue alterado")
    return titulo, contenido


def _descifrar_campo(clave: bytes, fila, campo: str) -> str | None:
    try:
        return simetrico.descifrar_texto(fila[f"{campo}_cifrado"], clave, contexto_documento(fila["usuario_id"], fila["id"], campo))
    except simetrico.ErrorCifrado:
        return None


def _validar(titulo: str, contenido: str) -> tuple[str, str]:
    titulo = (titulo or "").strip()
    contenido = (contenido or "").replace("\r\n", "\n")
    if not titulo:
        raise ErrorServicio("El título es obligatorio")
    if len(titulo) > TITULO_MAX:
        raise ErrorServicio(f"El título no puede superar {TITULO_MAX} caracteres")
    if len(contenido) > CONTENIDO_MAX:
        raise ErrorServicio(f"El contenido no puede superar {CONTENIDO_MAX} caracteres")
    return titulo, contenido
