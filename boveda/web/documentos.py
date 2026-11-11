"""Documentos: alta, edición, firma y certificado. Todas las rutas exigen sesión."""

import json

from flask import Blueprint, Response, abort, current_app, flash, g, redirect, render_template, request, url_for

from boveda.db import obtener_db
from boveda.servicios import documentos as servicio
from boveda.servicios.comun import ErrorServicio, NoEncontrado
from boveda.web.auth import requiere_sesion

bp = Blueprint("documentos", __name__, url_prefix="/documentos")


def _clave() -> bytes:
    return current_app.config["CLAVE_DATOS"]


def _documento(documento_id: str) -> servicio.Documento:
    try:
        return servicio.obtener(obtener_db(), _clave(), g.usuario["id"], documento_id)
    except NoEncontrado:
        abort(404)


@bp.get("")
@requiere_sesion
def lista():
    documentos = servicio.listar(obtener_db(), _clave(), g.usuario["id"])
    return render_template("documentos/lista.html", documentos=documentos)


@bp.route("/nuevo", methods=["GET", "POST"])
@requiere_sesion
def nuevo():
    valores = {"titulo": "", "contenido": ""}
    if request.method == "POST":
        valores = {"titulo": request.form.get("titulo", ""), "contenido": request.form.get("contenido", "")}
        try:
            documento_id = servicio.crear(obtener_db(), _clave(), g.usuario["id"], valores["titulo"], valores["contenido"])
        except ErrorServicio as e:
            flash(str(e), "error")
            return render_template("documentos/formulario.html", documento=None, valores=valores), 400
        flash("Documento cifrado y guardado", "ok")
        return redirect(url_for("documentos.detalle", documento_id=documento_id))
    return render_template("documentos/formulario.html", documento=None, valores=valores)


@bp.get("/<documento_id>")
@requiere_sesion
def detalle(documento_id: str):
    return render_template("documentos/detalle.html", doc=_documento(documento_id))


@bp.route("/<documento_id>/editar", methods=["GET", "POST"])
@requiere_sesion
def editar(documento_id: str):
    doc = _documento(documento_id)
    valores = {"titulo": doc.titulo, "contenido": doc.contenido}
    if request.method == "POST":
        valores = {"titulo": request.form.get("titulo", ""), "contenido": request.form.get("contenido", "")}
        try:
            cambio = servicio.actualizar(obtener_db(), _clave(), g.usuario["id"], documento_id, valores["titulo"], valores["contenido"])
        except ErrorServicio as e:
            flash(str(e), "error")
            return render_template("documentos/formulario.html", documento=doc, valores=valores), 400
        if not cambio:
            flash("No hubo cambios", "info")
        elif doc.firma:
            flash("Cambios guardados. La firma anterior se invalidó porque el contenido cambió.", "info")
        else:
            flash("Cambios guardados", "ok")
        return redirect(url_for("documentos.detalle", documento_id=documento_id))
    return render_template("documentos/formulario.html", documento=doc, valores=valores)


@bp.post("/<documento_id>/eliminar")
@requiere_sesion
def eliminar(documento_id: str):
    try:
        servicio.eliminar(obtener_db(), g.usuario["id"], documento_id)
    except NoEncontrado:
        abort(404)
    flash("Documento eliminado", "info")
    return redirect(url_for("documentos.lista"))


@bp.post("/<documento_id>/firmar")
@requiere_sesion
def firmar(documento_id: str):
    try:
        servicio.firmar(obtener_db(), _clave(), g.usuario["id"], documento_id, request.form.get("contrasena", ""))
    except NoEncontrado:
        abort(404)
    except ErrorServicio as e:
        flash(str(e), "error")
    else:
        flash("Documento firmado con tu llave privada Ed25519", "ok")
    return redirect(url_for("documentos.detalle", documento_id=documento_id))


@bp.get("/<documento_id>/certificado")
@requiere_sesion
def certificado(documento_id: str):
    try:
        cert = servicio.certificado(obtener_db(), _clave(), g.usuario["id"], documento_id)
    except NoEncontrado:
        abort(404)
    except ErrorServicio as e:
        flash(str(e), "error")
        return redirect(url_for("documentos.detalle", documento_id=documento_id))
    cuerpo = json.dumps(cert, ensure_ascii=False, indent=2)
    return Response(
        cuerpo,
        mimetype="application/json",
        headers={"Content-Disposition": f'attachment; filename="certificado-{documento_id[:8]}.json"'},
    )
