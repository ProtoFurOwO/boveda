# Diseño criptográfico de Bóveda

Este documento explica qué protege cada mecanismo, cómo funciona, dónde vive cada llave y qué queda fuera del alcance. Complementa el [README](../README.md).

## 1. Objetivo

Bóveda es una aplicación de mensajería entre usuarios. Protege los mensajes frente a cuatro amenazas:

1. Alguien obtiene la base de datos y quiere leer los mensajes.
2. Alguien altera un mensaje y quiere que no se note.
3. Alguien se hace pasar por el remitente de un mensaje o de un comprobante.
4. Un usuario quiere leer un mensaje que no es suyo.

## 2. Componentes

| Archivo | Responsabilidad |
|---|---|
| `boveda/criptografia/claves.py` | Carga la clave maestra y deriva subclaves con HKDF |
| `boveda/criptografia/simetrico.py` | AES-256-GCM: cifrado y descifrado autenticado |
| `boveda/criptografia/asimetrico.py` | Ed25519: generación de llaves, envoltura, firma, verificación y canonización |
| `boveda/criptografia/contrasenas.py` | scrypt: hash de contraseñas y derivación de la clave de envoltura |
| `boveda/servicios/usuarios.py` | Alta, autenticación y desbloqueo de la llave de firma |
| `boveda/servicios/mensajes.py` | Cifrado al enviar, descifrado al leer, firma y control de acceso |
| `boveda/servicios/comprobantes.py` | Formato del mensaje firmado y validación de comprobantes |
| `boveda/servicios/compartidos.py` | Enlaces públicos con token, caducidad y revocación |

La capa de servicios no depende de Flask. Eso permite probar la criptografía sin levantar un servidor.

## 3. Jerarquía de llaves

```
variable de entorno BOVEDA_CLAVE_MAESTRA   o   secretos/clave_maestra.key
                         │
                 clave maestra (256 bits)
                         │
                HKDF-SHA256 (info = "boveda/<propósito>")
              ┌──────────┴───────────┐
       clave de datos          clave de sesión
  (propósito: datos-mensajes)  (propósito: sesion-web)
              │                      │
   AES-256-GCM sobre asunto     firma de cookies de sesión
   y cuerpo de los mensajes     (Flask / itsdangerous)

contraseña del usuario ──scrypt (sal_llave)──► KEK (256 bits, solo en memoria)
KEK ──AES-256-GCM (AAD "llave-firma|<usuario>")──► llave privada Ed25519 (en la BD)
```

La clave maestra tiene 256 bits de entropía aleatoria. Por eso HKDF puede usarse sin sal (RFC 5869, sección 3.1). Cada propósito produce una clave distinta, así que comprometer la clave de sesión no revela la clave de datos.

## 4. Cifrado simétrico (AES-256-GCM)

### Qué se cifra

- El asunto y el cuerpo de cada mensaje.
- La llave privada de firma de cada usuario, dentro de la base de datos.

### Formato almacenado

```
v1:<nonce en base64, 12 bytes>:<cifrado + etiqueta en base64>
```

El prefijo `v1` permite cambiar de algoritmo en el futuro sin romper los datos existentes. La etiqueta de autenticación mide 128 bits.

### Datos asociados (AAD)

Cada cifrado se autentica junto con un contexto que no se cifra:

- Mensaje: `mensaje|<remitente_id>|<destinatario_id>|<mensaje_id>|<asunto o cuerpo>`
- Llave de firma: `llave-firma|<usuario_id>`

Si un cifrado se copia a otra fila, a otro destinatario o a otro campo, el contexto no coincide y el descifrado falla. La prueba `test_un_cifrado_no_se_puede_trasplantar_a_otro_mensaje` lo verifica.

### Por qué AES-GCM

- Es un cifrado autenticado (AEAD): el mismo paso que descifra también detecta cualquier alteración.
- Acepta datos asociados, que atan cada cifrado a su mensaje, remitente y destinatario.
- El nonce de 96 bits se genera al azar en cada cifrado. NIST recomienda no superar 2³² cifrados con la misma clave cuando los nonces son aleatorios. Bóveda está muy por debajo de ese límite.

Se descartó Fernet. Es más simple, pero no permite datos asociados y oculta el nonce y el formato.

## 5. Firma asimétrica (Ed25519)

### Llaves

- Al registrarse, cada usuario genera un par Ed25519 (RFC 8032). La llave privada mide 32 bytes y la firma 64.
- La llave pública se guarda en PEM (`SubjectPublicKeyInfo`) en la columna `clave_publica_pem`.
- La llave privada se guarda en PKCS#8 DER, cifrada con AES-256-GCM. La clave de envoltura (KEK) sale de la contraseña del usuario con scrypt y una sal propia. La KEK nunca se guarda.

### Qué se firma

Un JSON canónico: claves ordenadas, sin espacios y en UTF-8.

```json
{"asunto":"Clave de la reunión","creado_en":"2026-11-11T07:10:00+00:00",
 "cuerpo":"La clave es 4321","destinatario":"beto","firmado_en":"2026-11-11T07:10:00+00:00",
 "mensaje":"cd9f0606...","remitente":"ana","version":1}
```

Firma y verificación calculan exactamente los mismos bytes porque usan la misma función de canonización. Por eso el comprobante puede verificarse en otra máquina.

### Flujo de envío

1. El remitente elige un destinatario registrado y escribe su contraseña.
2. Se deriva la KEK con scrypt y la sal del usuario.
3. Se descifra la llave privada con la KEK. Si la contraseña es incorrecta, la etiqueta de GCM no coincide y el envío se rechaza antes de guardar nada.
4. Se cifran asunto y cuerpo con AES-256-GCM.
5. Se construye el payload canónico y se firma con Ed25519.
6. Se guarda el mensaje cifrado, la firma y la fecha. La llave privada no se guarda.

### Flujo de lectura

Solo el remitente o el destinatario pueden pedir el mensaje; el resto recibe un 404. Para quien sí puede:

1. Se descifran asunto y cuerpo.
2. Se reconstruye el payload canónico con los datos actuales de la base de datos.
3. Ed25519 verifica la firma con la clave pública registrada del remitente. Si el contenido, el remitente, el destinatario o la fecha cambiaron, falla.

### Comprobantes

Un comprobante es el payload más la firma, la clave pública del remitente y su huella SHA-256. Lo puede descargar el remitente o el destinatario. Quien lo recibe puede verificarlo sin la aplicación:

- Con `--clave-publica`, compara la huella del comprobante con la clave que él mismo obtuvo de una fuente de confianza. Si no coincide, el comprobante es falso aunque la firma sea válida. Eso prueba autoría.
- Sin esa opción, solo comprueba que la firma coincide con la clave incluida en el propio comprobante. Eso prueba integridad, pero no quién lo envió.

En la verificación pública de la aplicación, la clave de confianza es la registrada en la tabla de usuarios para el remitente. Por eso esa página sirve para comprobantes de la misma instalación. Si el comprobante viene de otra instalación, el remitente no estará registrado allí: se usa `scripts/verificar_comprobante.py` con la clave pública del remitente como fuente de confianza.

## 6. Enlaces compartidos

El remitente o el destinatario pueden crear un enlace público de solo lectura:

1. `crear_enlace` genera un token con `secrets.token_urlsafe(32)` (256 bits).
2. En la base se guarda `sha256(token)`, no el token. El token se muestra una sola vez.
3. El enlace caduca a los 7 días y se puede revocar (`revocado_en`).
4. `resolver_enlace` busca por hash, comprueba que no esté revocado ni caducado y carga el mensaje con `mensajes.obtener_por_id`. La autorización la da el token.
5. La página `/p/<token>` descifra y verifica la firma; es de solo lectura. No permite editar ni firmar.
6. Si el mensaje se elimina, `ON DELETE CASCADE` borra sus enlaces.
7. Las respuestas llevan `Referrer-Policy: no-referrer`, `X-Robots-Tag: noindex, nofollow` y `Cache-Control: no-store`. Un token inválido, caducado o revocado responde 404.
8. El enlace es un secreto portador: quien lo tenga puede leer. No se indexa, no se lista y no se usa el ID del mensaje en la URL.

### Alteración de un mensaje compartido

La página vuelve a descifrar y verificar en cada visita. Si alguien con la clave maestra cambia el texto y lo vuelve a cifrar, el enlace muestra *Alterado* y una advertencia. Si copia el cifrado a otro mensaje, el AAD no coincide y no se puede descifrar. El comprobante descargado antes conserva la prueba del texto original.

## 7. Contraseñas (scrypt)

- Parámetros: N=2¹⁷, r=8, p=1, 32 bytes de salida, sal de 16 bytes por usuario. Son los valores que recomienda OWASP. En la máquina de desarrollo, una derivación tarda unos 0.36 s.
- Formato del hash: `scrypt$<N>$<r>$<p>$<sal>$<hash>`. Los parámetros van en el hash para poder subirlos en el futuro.
- Hay dos derivaciones independientes con sales distintas: una para verificar el inicio de sesión y otra para la KEK. El hash nunca se usa como clave.
- Si el usuario no existe, el inicio de sesión calcula igualmente un hash señuelo. Así el tiempo de respuesta no revela si la cuenta existe.

## 8. Gestión de llaves

### Clave maestra

Orden de búsqueda:

1. Variable de entorno `BOVEDA_CLAVE_MAESTRA` (base64, 32 bytes).
2. Archivo indicado por `BOVEDA_CLAVE_ARCHIVO`. Por defecto, `secretos/clave_maestra.key`.
3. Si no existe ninguna, se genera 32 bytes aleatorios y se escriben en el archivo con creación exclusiva (`O_EXCL`), para que nunca sobrescriban una clave existente.

Si la variable existe pero no es válida, la aplicación se detiene con un mensaje que no muestra la clave.

Permisos del archivo: `chmod 600` en Linux y macOS. En Windows se usa `icacls` para quitar la herencia y dar control total solo al usuario actual. Si `icacls` falla, la aplicación avisa en la consola.

La aplicación nunca escribe la clave en logs, en la base de datos ni en las páginas. La página *Seguridad* muestra el origen y una huella SHA-256 truncada de 16 caracteres, que identifica la clave sin revelarla.

### Respaldo y pérdida

Sin la clave maestra no se pueden leer los mensajes. Respáldala fuera del proyecto. Si cambia, la aplicación sigue funcionando, pero los mensajes existentes no se descifran y aparecen como alterados.

### Lo que no está implementado

- Rotación de la clave maestra. Haría falta re-cifrar todos los mensajes con la clave nueva.
- Recuperación de contraseñas. Como la llave privada depende de la contraseña, un usuario que la olvida ya no puede firmar mensajes nuevos. Los comprobantes descargados antes siguen verificándose con su clave pública.
- Un HSM o un KMS en la nube. El código los permitiría: solo habría que cambiar la función `cargar_clave_maestra`.

## 9. Modelo de amenazas

| Amenaza | Qué pasaría | Mitigación | Límite |
|---|---|---|---|
| Robo del archivo `data/boveda.db` | El atacante ve usuarios, hashes, llaves privadas envueltas y mensajes cifrados | Contenido en AES-256-GCM. Hashes con scrypt. Llaves privadas cifradas con la contraseña. La clave maestra no está en la base de datos. | Una contraseña débil se puede adivinar sin conexión. scrypt encarece cada intento, pero no lo impide. |
| Alteración de un mensaje en la base de datos sin la clave maestra | Se corrompe el cifrado | AES-GCM detecta la corrupción al descifrar | Ninguno para este caso |
| Alteración con la clave maestra (cambiar el texto y volver a cifrarlo) | El descifrado funciona y el texto cambió | La firma Ed25519 no coincide y el sello muestra *Alterado* | Si alguien borra la firma, el mensaje queda como *Sin firma*. Un comprobante emitido antes conserva la prueba del texto original. |
| Copiar un cifrado a otro mensaje o campo | El texto aparece en otro lugar | Datos asociados con remitente, destinatario, mensaje y campo | Ninguno para este caso |
| Falsificar una firma sin conocer la contraseña | El atacante quiere enviar como otro usuario | La llave privada solo se abre con la contraseña | Quien conozca la contraseña del remitente puede firmar |
| Comprobante falso con una llave propia | El verificador ve una firma válida | La verificación pública exige que la clave coincida con la registrada del remitente | Sin la aplicación, el verificador debe conseguir la clave del remitente por otra vía |
| Tercer usuario pide un mensaje ajeno por su identificador (IDOR) | Querría leer un mensaje que no es suyo | Todas las consultas filtran por remitente o destinatario. Responde 404. | Ninguno para este caso |
| Adivinar un enlace compartido | Querría abrir un mensaje ajeno probando IDs o tokens | Token de 256 bits, el ID del mensaje no aparece en la URL, 404 para cualquier token inválido, no hay listado de enlaces | Si el enlace se filtra, quien lo tenga puede leer el mensaje |
| Enlace público filtrado o indexado | El mensaje se vuelve público | Token aleatorio, caducidad de 7 días, revocación, `noindex`, `no-referrer`, `no-store` | Es un secreto portador: si se reenvía, no se puede impedir la lectura; hay que revocarlo |
| Enlace de un mensaje eliminado | Seguir leyendo después de borrar | `ON DELETE CASCADE`; el enlace deja de existir | Ninguno para este caso |
| Alteración de un mensaje ya compartido | El visitante del enlace ve contenido falso | Se descifra y verifica en cada visita; sello *Alterado* y advertencia | Si el atacante controla la base y borra la firma, el mensaje queda *Sin firma*; el comprobante previo conserva la prueba |
| Fuga de la clave maestra | Se descifran todos los mensajes y se pueden alterar | La clave vive fuera del código y de la base de datos, con permisos restringidos | Una sola clave raíz. No hay rotación. El servidor puede leer los mensajes: es cifrado en reposo, no extremo a extremo. |
| Fuerza bruta contra el inicio de sesión | Intentos repetidos de contraseña | scrypt hace cada intento costoso | No hay límite de intentos ni bloqueo temporal |
| Inyección de scripts (XSS) | Código ajeno se ejecuta en el navegador | Autoescape de Jinja2. CSP sin scripts en línea. | Ninguno para este caso |
| Falsificación de peticiones (CSRF) | Un sitio ajeno envía formularios en nombre del usuario | Token por sesión comparado en tiempo constante. `SameSite=Lax` en la cookie. | Ninguno para este caso |
| Incrustación en otro sitio (clickjacking) | La página se muestra dentro de un iframe | `X-Frame-Options: DENY` y `frame-ancestors 'none'` | Ninguno para este caso |
| Robo de la cookie de sesión | Un tercero entra como el usuario | `HttpOnly`, `SameSite=Lax`, expiración tras 60 minutos de inactividad y `Secure` configurable | Sin HTTPS en local, la cookie viaja en claro por la red |
| Enumeración de usuarios | Saber qué cuentas existen | El inicio de sesión tarda lo mismo para usuarios inexistentes | El formulario de mensaje nuevo muestra los usuarios registrados como posibles destinatarios |
| Eliminación de un mensaje | Perder la prueba del contenido | El remitente o el destinatario pueden descargar el comprobante antes de borrarlo | Borrar elimina el mensaje para ambos; solo el comprobante externo conserva la prueba |

## 10. Decisiones y alternativas

| Decisión | Alternativa descartada | Motivo |
|---|---|---|
| AES-256-GCM con datos asociados | Fernet | Fernet no permite datos asociados, así que no ata cada cifrado a su mensaje y destinatario |
| Ed25519 | RSA-2048 o RSA-PSS | Claves y firmas más pequeñas, firmas deterministas y un estándar moderno (RFC 8032). RSA-PSS también sería válido. |
| Una llave de firma por usuario | Una sola llave del servidor | La firma prueba autoría, no solo que el sistema emitió el mensaje |
| Llave privada cifrada con la contraseña | Llave privada cifrada solo con la clave maestra | Quien tenga la clave maestra no puede firmar como el usuario sin conocer su contraseña |
| Mensajes inmutables | Permitir editar | Un mensaje editado dejaría de ser una prueba de lo que se dijo; para corregir se envía otro |
| Enlace público con token y hash en la base | Guardar el token o usar el ID del mensaje en la URL | El token no queda en la base, el ID no se expone y el enlace se puede revocar |
| Enlaces de 7 días y revocables | URL pública permanente | Reduce la ventana de exposición y permite cortar el acceso |
| Página pública de solo lectura | Compartir solo con una cuenta concreta | Cualquiera con el enlace puede verlo sin registro; es una decisión explícita del usuario |
| Cookie de sesión firmada por Flask | JWT firmado con EdDSA | Un JWT sería un tercer mecanismo fuera del alcance. La sesión ya está firmada y expira. |
| Clave de sesión derivada con HKDF | Variable de entorno aparte para `SECRET_KEY` | Una sola raíz de confianza: la clave maestra |
| waitress como servidor | Servidor de desarrollo de Flask | waitress es un servidor WSGI de producción que funciona en Windows, Linux y macOS |
| SQLite | PostgreSQL | Suficiente para la práctica. La capa de acceso está aislada en `db.py` y los servicios. |

## 11. Verificación

- **Pruebas automáticas:** 59 pruebas con `python -m pytest`. Cubren cifrado, firma, claves, servicios, comprobantes, enlaces compartidos y el flujo web.
- **Demostración en consola:** `python scripts/demostracion.py` recorre el envío entre dos usuarios, el comprobante, el enlace público, la alteración, la revocación y el trasplante de cifrado con una base y una clave temporales.
- **Demostración en la aplicación:** los scripts `manipular_mensaje.py` y `verificar_comprobante.py` simulan ataques sobre la base real y sobre comprobantes.
- **Revisión visual:** se recorrieron la bandeja, el envío y el mensaje firmado en un navegador. La alteración y la verificación pública se cubren con las pruebas automáticas.
- **Revisión del enlace público:** se comprobó por HTTP el estado 200, las cabeceras de privacidad, la alteración y la revocación; `tests/test_compartidos.py` cubre el resto.

## 12. Referencias

- NIST SP 800-38D: *Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM)*.
- RFC 8032: *Edwards-Curve Digital Signature Algorithm (EdDSA)*.
- RFC 5869: *HMAC-based Extract-and-Expand Key Derivation Function (HKDF)*.
- RFC 7914: *The scrypt Password-Based Key Derivation Function*.
- OWASP, *Password Storage Cheat Sheet*: parámetros recomendados para scrypt.
- Documentación de la librería `cryptography`: <https://cryptography.io/en/latest/hazmat/primitives/>.
