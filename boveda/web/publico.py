"""Páginas públicas: inicio, verificación de comprobantes y transparencia de seguridad."""

import json

from flask import Blueprint, abort, current_app, flash, g, redirect, render_template, request, url_for

from boveda.criptografia import asimetrico
from boveda.db import obtener_db
from boveda.servicios import compartidos, comprobantes, usuarios
from boveda.servicios.comun import ErrorServicio, NoEncontrado

bp = Blueprint("publico", __name__)


@bp.get("/")
def inicio():
    return redirect(url_for("mensajes.lista" if g.usuario else "auth.login"))


@bp.route("/verificar", methods=["GET", "POST"])
def verificar():
    resultado = None
    if request.method == "POST":
        try:
            resultado = _verificar_subida()
        except ErrorServicio as e:
            flash(str(e), "error")
    return render_template("verificar.html", resultado=resultado)


@bp.get("/p/<token>")
def compartido(token: str):
    try:
        enlace = compartidos.resolver_enlace(obtener_db(), current_app.config["CLAVE_DATOS"], token)
    except NoEncontrado:
        abort(404)
    return render_template("compartido.html", enlace=enlace)


@bp.get("/seguridad")
def seguridad():
    total = obtener_db().execute("SELECT COUNT(*) FROM mensajes").fetchone()[0]
    return render_template("seguridad.html", total_mensajes=total)


def _verificar_subida() -> comprobantes.ResultadoVerificacion:
    archivo = request.files.get("comprobante")
    if archivo is None or not archivo.filename:
        raise ErrorServicio("Selecciona un archivo de comprobante (.json)")
    try:
        datos = json.loads(archivo.read().decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ErrorServicio("El archivo no es un JSON válido") from e
    if not isinstance(datos, dict) or not isinstance(datos.get("payload"), dict):
        raise ErrorServicio("El archivo no es un comprobante de Bóveda")
    remitente = datos["payload"].get("remitente")
    registrado = usuarios.buscar_por_nombre(obtener_db(), remitente) if isinstance(remitente, str) else None
    if registrado is None:
        raise ErrorServicio(
            "El remitente del comprobante no está registrado en esta bóveda: no es posible confirmar su clave pública"
        )
    clave = asimetrico.cargar_publica(registrado["clave_publica_pem"])
    return comprobantes.validar(datos, clave)
