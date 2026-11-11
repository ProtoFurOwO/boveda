document.addEventListener("submit", function (evento) {
  var mensaje = evento.target.getAttribute("data-confirmar");
  if (mensaje && !window.confirm(mensaje)) {
    evento.preventDefault();
  }
});

document.addEventListener("click", function (evento) {
  var boton = evento.target.closest("[data-copiar]");
  if (!boton) return;
  var texto = boton.getAttribute("data-copiar");
  var original = boton.textContent;
  copiar(texto).then(function () {
    boton.textContent = "Copiado";
    window.setTimeout(function () {
      boton.textContent = original;
    }, 1800);
  }).catch(function () {
    boton.textContent = "Selecciona y copia";
  });
});

function copiar(texto) {
  if (navigator.clipboard && window.isSecureContext) {
    return navigator.clipboard.writeText(texto);
  }
  var area = document.createElement("textarea");
  area.value = texto;
  area.setAttribute("readonly", "");
  area.style.position = "fixed";
  area.style.opacity = "0";
  document.body.appendChild(area);
  area.select();
  document.execCommand("copy");
  document.body.removeChild(area);
  return Promise.resolve();
}
