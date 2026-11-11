"""Registro, inicio y cierre de sesión."""

import functools

from flask import Blueprint, flash, g, redirect, render_template, request, session, url_for

from boveda.db import obtener_db
from boveda.servicios import usuarios
from boveda.servicios.comun import ErrorServicio

bp = Blueprint("auth", __name__)


def requiere_sesion(vista):
    @functools.wraps(vista)
    def envuelta(*args, **kwargs):
        if g.usuario is None:
            flash("Inicia sesión para continuar", "info")
            return redirect(url_for("auth.login"))
        return vista(*args, **kwargs)

    return envuelta


@bp.route("/registro", methods=["GET", "POST"])
def registro():
    if g.usuario is not None:
        return redirect(url_for("mensajes.lista"))
    if request.method == "POST":
        nombre = request.form.get("nombre", "")
        contrasena = request.form.get("contrasena", "")
        try:
            if contrasena != request.form.get("confirmacion", ""):
                raise ErrorServicio("Las contraseñas no coinciden")
            usuario_id = usuarios.registrar(obtener_db(), nombre, contrasena)
        except ErrorServicio as e:
            flash(str(e), "error")
            return render_template("registro.html", nombre=nombre), 400
        _iniciar_sesion(usuario_id)
        flash("Cuenta creada. Tu llave de firma Ed25519 se generó y se guarda cifrada con tu contraseña.", "ok")
        return redirect(url_for("mensajes.lista"))
    return render_template("registro.html", nombre="")


@bp.route("/login", methods=["GET", "POST"])
def login():
    if g.usuario is not None:
        return redirect(url_for("mensajes.lista"))
    if request.method == "POST":
        nombre = request.form.get("nombre", "")
        fila = usuarios.autenticar(obtener_db(), nombre, request.form.get("contrasena", ""))
        if fila is None:
            flash("Usuario o contraseña incorrectos", "error")
            return render_template("login.html", nombre=nombre), 401
        _iniciar_sesion(fila["id"])
        return redirect(url_for("mensajes.lista"))
    return render_template("login.html", nombre="")


@bp.post("/salir")
def salir():
    session.clear()
    flash("Sesión cerrada", "info")
    return redirect(url_for("auth.login"))


def _iniciar_sesion(usuario_id: str) -> None:
    session.clear()
    session.permanent = True
    session["usuario_id"] = usuario_id
