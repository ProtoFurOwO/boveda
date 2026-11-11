"""Mensajes: bandeja de recibidos y enviados, envío firmado y comprobantes."""

import json

from flask import Blueprint, Response, abort, current_app, flash, g, redirect, render_template, request, session, url_for

from boveda.db import obtener_db
from boveda.servicios import compartidos as servicio_compartidos
from boveda.servicios import mensajes as servicio
from boveda.servicios import usuarios
from boveda.servicios.comun import ErrorServicio, NoEncontrado
from boveda.web.auth import requiere_sesion

bp = Blueprint("mensajes", __name__, url_prefix="/mensajes")


def _clave() -> bytes:
    return current_app.config["CLAVE_DATOS"]


def _mensaje(mensaje_id: str) -> servicio.Mensaje:
    try:
        return servicio.obtener(obtener_db(), _clave(), g.usuario["id"], mensaje_id)
    except NoEncontrado:
        abort(404)


def _destinatarios() -> list:
    return [u for u in usuarios.listar(obtener_db()) if u["id"] != g.usuario["id"]]


@bp.get("")
@requiere_sesion
def lista():
    bandeja = request.args.get("bandeja", "recibidos")
    if bandeja not in servicio.BANDEJAS:
        bandeja = "recibidos"
    mensajes = servicio.listar(obtener_db(), _clave(), g.usuario["id"], bandeja)
    return render_template("mensajes/lista.html", mensajes=mensajes, bandeja=bandeja)


@bp.route("/nuevo", methods=["GET", "POST"])
@requiere_sesion
def nuevo():
    destinatarios = _destinatarios()
    valores = {"destinatario": request.args.get("para", ""), "asunto": "", "cuerpo": ""}
    if request.method == "POST":
        valores = {
            "destinatario": request.form.get("destinatario", ""),
            "asunto": request.form.get("asunto", ""),
            "cuerpo": request.form.get("cuerpo", ""),
        }
        try:
            mensaje_id = servicio.enviar(
                obtener_db(),
                _clave(),
                g.usuario["id"],
                valores["destinatario"],
                valores["asunto"],
                valores["cuerpo"],
                request.form.get("contrasena", ""),
            )
        except ErrorServicio as e:
            flash(str(e), "error")
            return render_template("mensajes/formulario.html", destinatarios=destinatarios, valores=valores), 400
        flash("Mensaje cifrado, firmado y enviado", "ok")
        return redirect(url_for("mensajes.detalle", mensaje_id=mensaje_id))
    return render_template("mensajes/formulario.html", destinatarios=destinatarios, valores=valores)


@bp.get("/<mensaje_id>")
@requiere_sesion
def detalle(mensaje_id: str):
    return _render_detalle(_mensaje(mensaje_id))


@bp.post("/<mensaje_id>/compartir")
@requiere_sesion
def compartir(mensaje_id: str):
    try:
        enlace = servicio_compartidos.crear_enlace(obtener_db(), mensaje_id, g.usuario["id"])
    except NoEncontrado:
        abort(404)
    session["enlace_nuevo"] = {
        "mensaje_id": mensaje_id,
        "url": url_for("publico.compartido", token=enlace.token, _external=True),
        "expira_en": enlace.expira_en,
    }
    flash("Enlace creado. Cópialo ahora: no se volverá a mostrar.", "ok")
    return redirect(url_for("mensajes.detalle", mensaje_id=mensaje_id))


@bp.post("/<mensaje_id>/compartir/<enlace_id>/revocar")
@requiere_sesion
def revocar(mensaje_id: str, enlace_id: str):
    try:
        servicio_compartidos.revocar_enlace(obtener_db(), mensaje_id, enlace_id, g.usuario["id"])
    except NoEncontrado:
        abort(404)
    flash("Enlace revocado", "info")
    return redirect(url_for("mensajes.detalle", mensaje_id=mensaje_id))


def _render_detalle(mensaje: servicio.Mensaje):
    enlace_nuevo = session.pop("enlace_nuevo", None)
    if enlace_nuevo and enlace_nuevo.get("mensaje_id") != mensaje.id:
        enlace_nuevo = None
    enlaces = servicio_compartidos.listar_enlaces(obtener_db(), mensaje.id, g.usuario["id"])
    responder_a = mensaje.destinatario if mensaje.remitente == g.usuario["nombre"] else mensaje.remitente
    return render_template(
        "mensajes/detalle.html",
        mensaje=mensaje,
        responder_a=responder_a,
        enlaces=enlaces,
        enlace_nuevo=enlace_nuevo,
    )


@bp.post("/<mensaje_id>/eliminar")
@requiere_sesion
def eliminar(mensaje_id: str):
    try:
        servicio.eliminar(obtener_db(), g.usuario["id"], mensaje_id)
    except NoEncontrado:
        abort(404)
    flash("Mensaje eliminado para el remitente y el destinatario", "info")
    return redirect(url_for("mensajes.lista"))


@bp.get("/<mensaje_id>/comprobante")
@requiere_sesion
def comprobante(mensaje_id: str):
    try:
        datos = servicio.comprobante(obtener_db(), _clave(), g.usuario["id"], mensaje_id)
    except NoEncontrado:
        abort(404)
    except ErrorServicio as e:
        flash(str(e), "error")
        return redirect(url_for("mensajes.detalle", mensaje_id=mensaje_id))
    cuerpo = json.dumps(datos, ensure_ascii=False, indent=2)
    return Response(
        cuerpo,
        mimetype="application/json",
        headers={"Content-Disposition": f'attachment; filename="comprobante-{mensaje_id[:8]}.json"'},
    )
