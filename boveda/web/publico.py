"""Páginas públicas: inicio, verificación de certificados y transparencia de seguridad."""

import json

from flask import Blueprint, flash, g, redirect, render_template, request, url_for

from boveda.criptografia import asimetrico
from boveda.db import obtener_db
from boveda.servicios import certificados, usuarios
from boveda.servicios.comun import ErrorServicio

bp = Blueprint("publico", __name__)


@bp.get("/")
def inicio():
    return redirect(url_for("documentos.lista" if g.usuario else "auth.login"))


@bp.route("/verificar", methods=["GET", "POST"])
def verificar():
    resultado = None
    if request.method == "POST":
        try:
            resultado = _verificar_subida()
        except ErrorServicio as e:
            flash(str(e), "error")
    return render_template("verificar.html", resultado=resultado)


@bp.get("/seguridad")
def seguridad():
    total = obtener_db().execute("SELECT COUNT(*) FROM documentos").fetchone()[0]
    return render_template("seguridad.html", total_documentos=total)


def _verificar_subida() -> certificados.ResultadoVerificacion:
    archivo = request.files.get("certificado")
    if archivo is None or not archivo.filename:
        raise ErrorServicio("Selecciona un archivo de certificado (.json)")
    try:
        datos = json.loads(archivo.read().decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ErrorServicio("El archivo no es un JSON válido") from e
    if not isinstance(datos, dict) or not isinstance(datos.get("payload"), dict):
        raise ErrorServicio("El archivo no es un certificado de Bóveda")
    autor = datos["payload"].get("autor")
    registrado = usuarios.buscar_por_nombre(obtener_db(), autor) if isinstance(autor, str) else None
    if registrado is None:
        raise ErrorServicio("El autor del certificado no está registrado en esta bóveda: no es posible confirmar su clave pública")
    clave = asimetrico.cargar_publica(registrado["clave_publica_pem"])
    return certificados.validar(datos, clave)
