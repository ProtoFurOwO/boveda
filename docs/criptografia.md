# Diseño criptográfico de Bóveda

Este documento explica qué protege cada mecanismo, cómo funciona, dónde vive cada llave y qué queda fuera del alcance. Complementa el [README](../README.md).

## 1. Objetivo

Bóveda protege documentos sensibles frente a tres amenazas:

1. Alguien obtiene la base de datos y quiere leer los documentos.
2. Alguien altera un documento y quiere que no se note.
3. Alguien se hace pasar por el autor de un documento o de un certificado.

## 2. Componentes

| Archivo | Responsabilidad |
|---|---|
| `boveda/criptografia/claves.py` | Carga la clave maestra y deriva subclaves con HKDF |
| `boveda/criptografia/simetrico.py` | AES-256-GCM: cifrado y descifrado autenticado |
| `boveda/criptografia/asimetrico.py` | Ed25519: generación de llaves, envoltura, firma, verificación y canonización |
| `boveda/criptografia/contrasenas.py` | scrypt: hash de contraseñas y derivación de la clave de envoltura |
| `boveda/servicios/usuarios.py` | Alta, autenticación y desbloqueo de la llave de firma |
| `boveda/servicios/documentos.py` | Cifrado al guardar, descifrado al leer, firma y estado de la firma |
| `boveda/servicios/certificados.py` | Formato del documento firmado y validación de certificados |

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
    (propósito: datos-documentos)  (propósito: sesion-web)
              │                      │
   AES-256-GCM sobre título     firma de cookies de sesión
   y contenido de documentos    (Flask / itsdangerous)

contraseña del usuario ──scrypt (sal_llave)──► KEK (256 bits, solo en memoria)
KEK ──AES-256-GCM (AAD "llave-firma|<usuario>")──► llave privada Ed25519 (en la BD)
```

La clave maestra tiene 256 bits de entropía aleatoria. Por eso HKDF puede usarse sin sal (RFC 5869, sección 3.1). Cada propósito produce una clave distinta, así que comprometer la clave de sesión no revela la clave de datos.

## 4. Cifrado simétrico (AES-256-GCM)

### Qué se cifra

- El título y el contenido de cada documento.
- La llave privada de firma de cada usuario, dentro de la base de datos.

### Formato almacenado

```
v1:<nonce en base64, 12 bytes>:<cifrado + etiqueta en base64>
```

El prefijo `v1` permite cambiar de algoritmo en el futuro sin romper los datos existentes. La etiqueta de autenticación mide 128 bits.

### Datos asociados (AAD)

Cada cifrado se autentica junto con un contexto que no se cifra:

- Documento: `documento|<usuario_id>|<documento_id>|<titulo o contenido>`
- Llave de firma: `llave-firma|<usuario_id>`

Si un cifrado se copia a otra fila o a otro campo, el contexto no coincide y el descifrado falla. La prueba `test_un_cifrado_no_se_puede_trasplantar_a_otro_documento` lo verifica.

### Por qué AES-GCM

- Es un cifrado autenticado (AEAD): el mismo paso que descifra también detecta cualquier alteración.
- Acepta datos asociados, que atan cada cifrado a su documento y campo.
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
{"autor":"ana","contenido":"...","creado_en":"2026-11-11T06:51:45+00:00",
 "documento":"61446d1a...","firmado_en":"2026-11-11T06:55:02+00:00",
 "titulo":"...","version":1}
```

Firma y verificación calculan exactamente los mismos bytes porque usan la misma función de canonización. Por eso el certificado puede verificarse en otra máquina.

### Flujo de firma

1. El usuario escribe su contraseña.
2. Se deriva la KEK con scrypt y la sal del usuario.
3. Se descifra la llave privada con la KEK. Si la contraseña es incorrecta, la etiqueta de GCM no coincide y la firma se rechaza.
4. Se descifran título y contenido, y se construye el payload canónico con la fecha de firma.
5. Ed25519 firma el payload. La firma y la fecha se guardan en el documento.
6. La referencia a la llave privada se descarta. Python no garantiza borrar la memoria de inmediato, así que esto es una limitación conocida.

### Flujo de verificación

La verificación no pide contraseña. Usa la clave pública registrada del autor:

1. Se descifran título y contenido.
2. Se reconstruye el payload canónico con los datos actuales de la base de datos.
3. Ed25519 verifica la firma. Si el contenido, el autor o la fecha cambiaron, falla.

### Certificados

Un certificado es el payload más la firma, la clave pública del autor y su huella SHA-256. Quien lo recibe puede verificarlo sin la aplicación:

- Con `--clave-publica`, compara la huella del certificado con la clave que él mismo obtuvo de una fuente de confianza. Si no coincide, el certificado es falso aunque la firma sea válida. Eso prueba autoría.
- Sin esa opción, solo comprueba que la firma coincide con la clave incluida en el propio certificado. Eso prueba integridad, pero no quién firmó.

En la verificación pública de la aplicación, la clave de confianza es la registrada en la tabla de usuarios.

## 6. Contraseñas (scrypt)

- Parámetros: N=2¹⁷, r=8, p=1, 32 bytes de salida, sal de 16 bytes por usuario. Son los valores que recomienda OWASP. En la máquina de desarrollo, una derivación tarda unos 0.36 s.
- Formato del hash: `scrypt$<N>$<r>$<p>$<sal>$<hash>`. Los parámetros van en el hash para poder subirlos en el futuro.
- Hay dos derivaciones independientes con sales distintas: una para verificar el inicio de sesión y otra para la KEK. El hash nunca se usa como clave.
- Si el usuario no existe, el inicio de sesión calcula igualmente un hash señuelo. Así el tiempo de respuesta no revela si la cuenta existe.

## 7. Gestión de llaves

### Clave maestra

Orden de búsqueda:

1. Variable de entorno `BOVEDA_CLAVE_MAESTRA` (base64, 32 bytes).
2. Archivo indicado por `BOVEDA_CLAVE_ARCHIVO`. Por defecto, `secretos/clave_maestra.key`.
3. Si no existe ninguna, se genera 32 bytes aleatorios y se escriben en el archivo con creación exclusiva (`O_EXCL`), para que nunca sobrescriban una clave existente.

Si la variable existe pero no es válida, la aplicación se detiene con un mensaje que no muestra la clave.

Permisos del archivo: `chmod 600` en Linux y macOS. En Windows se usa `icacls` para quitar la herencia y dar control total solo al usuario actual. Si `icacls` falla, la aplicación avisa en la consola.

La aplicación nunca escribe la clave en logs, en la base de datos ni en las páginas. La página *Seguridad* muestra el origen y una huella SHA-256 truncada de 16 caracteres, que identifica la clave sin revelarla.

### Respaldo y pérdida

Sin la clave maestra no se pueden leer los documentos. Respáldala fuera del proyecto. Si cambia, la aplicación sigue funcionando, pero los documentos existentes no se descifran y aparecen como alterados.

### Lo que no está implementado

- Rotación de la clave maestra. Haría falta re-cifrar todos los documentos con la clave nueva.
- Recuperación de contraseñas. Como la llave privada depende de la contraseña, un usuario que la olvida ya no puede firmar. Los documentos firmados antes siguen verificándose con su clave pública.
- Un HSM o un KMS en la nube. El código los permitiría: solo habría que cambiar la función `cargar_clave_maestra`.

## 8. Modelo de amenazas

| Amenaza | Qué pasaría | Mitigación | Límite |
|---|---|---|---|
| Robo del archivo `data/boveda.db` | El atacante ve usuarios, hashes, llaves privadas envueltas y documentos cifrados | Contenido en AES-256-GCM. Hashes con scrypt. Llaves privadas cifradas con la contraseña. La clave maestra no está en la base de datos. | Una contraseña débil se puede adivinar sin conexión. scrypt encarece cada intento, pero no lo impide. |
| Alteración de un documento en la base de datos sin la clave maestra | Se corrompe el cifrado | AES-GCM detecta la corrupción al descifrar | Ninguno para este caso |
| Alteración con la clave maestra (cambiar el texto y volver a cifrarlo) | El descifrado funciona y el texto cambió | La firma Ed25519 no coincide y el sello muestra *Alterado* | Si alguien borra la firma, el documento queda como *Sin firmar*. Un certificado emitido antes conserva la prueba del texto original. |
| Copiar un cifrado a otro documento o campo | El texto aparece en otro lugar | Datos asociados con usuario, documento y campo | Ninguno para este caso |
| Falsificar una firma sin conocer la contraseña | El atacante quiere firmar como otro usuario | La llave privada solo se abre con la contraseña | Quien conozca la contraseña del autor puede firmar |
| Certificado falso con una llave propia | El verificador ve una firma válida | La verificación pública exige que la clave coincida con la registrada del autor | Sin la aplicación, el verificador debe conseguir la clave del autor por otra vía |
| Fuga de la clave maestra | Se descifran todos los documentos y se pueden alterar | La clave vive fuera del código y de la base de datos, con permisos restringidos | Una sola clave raíz. No hay rotación. |
| Fuerza bruta contra el inicio de sesión | Intentos repetidos de contraseña | scrypt hace cada intento costoso | No hay límite de intentos ni bloqueo temporal |
| Inyección de scripts (XSS) | Código ajeno se ejecuta en el navegador | Autoescape de Jinja2. CSP sin scripts en línea. | Ninguno para este caso |
| Falsificación de peticiones (CSRF) | Un sitio ajeno envía formularios en nombre del usuario | Token por sesión comparado en tiempo constante. `SameSite=Lax` en la cookie. | Ninguno para este caso |
| Incrustación en otro sitio (clickjacking) | La página se muestra dentro de un iframe | `X-Frame-Options: DENY` y `frame-ancestors 'none'` | Ninguno para este caso |
| Robo de la cookie de sesión | Un tercero entra como el usuario | `HttpOnly`, `SameSite=Lax`, expiración tras 60 minutos de inactividad y `Secure` configurable | Sin HTTPS en local, la cookie viaja en claro por la red |
| Lectura de documentos de otro usuario (IDOR) | Un usuario pide el identificador de otro | Todas las consultas filtran por usuario. Responde 404 si no es suyo. | Ninguno para este caso |
| Enumeración de usuarios | Saber qué cuentas existen | El inicio de sesión tarda lo mismo para usuarios inexistentes | El registro sí revela si un nombre está ocupado |

## 9. Decisiones y alternativas

| Decisión | Alternativa descartada | Motivo |
|---|---|---|
| AES-256-GCM con datos asociados | Fernet | Fernet no permite datos asociados, así que no ata cada cifrado a su documento |
| Ed25519 | RSA-2048 o RSA-PSS | Claves y firmas más pequeñas, firmas deterministas y un estándar moderno (RFC 8032). RSA-PSS también sería válido. |
| Una llave de firma por usuario | Una sola llave del servidor | La firma prueba autoría, no solo que el sistema emitió el documento |
| Llave privada cifrada con la contraseña | Llave privada cifrada solo con la clave maestra | Quien tenga la clave maestra no puede firmar como el usuario sin conocer su contraseña |
| Cookie de sesión firmada por Flask | JWT firmado con EdDSA | Un JWT sería un tercer mecanismo fuera del alcance. La sesión ya está firmada y expira. |
| Clave de sesión derivada con HKDF | Variable de entorno aparte para `SECRET_KEY` | Una sola raíz de confianza: la clave maestra |
| waitress como servidor | Servidor de desarrollo de Flask | waitress es un servidor WSGI de producción que funciona en Windows, Linux y macOS |
| SQLite | PostgreSQL | Suficiente para la práctica. La capa de acceso está aislada en `db.py` y los servicios. |

## 10. Verificación

- **Pruebas automáticas:** 44 pruebas con `python -m pytest`. Cubren cifrado, firma, claves, servicios, certificados y el flujo web.
- **Demostración en consola:** `python scripts/demostracion.py` recorre el flujo completo con una base y una clave temporales.
- **Demostración en la aplicación:** los scripts `manipular_documento.py` y `verificar_certificado.py` simulan ataques sobre la base real y sobre certificados.
- **Revisión visual:** se recorrieron las pantallas principales en un navegador, con y sin firma, con un documento alterado y en vista móvil.

## 11. Referencias

- NIST SP 800-38D: *Recommendation for Block Cipher Modes of Operation: Galois/Counter Mode (GCM)*.
- RFC 8032: *Edwards-Curve Digital Signature Algorithm (EdDSA)*.
- RFC 5869: *HMAC-based Extract-and-Expand Key Derivation Function (HKDF)*.
- RFC 7914: *The scrypt Password-Based Key Derivation Function*.
- OWASP, *Password Storage Cheat Sheet*: parámetros recomendados para scrypt.
- Documentación de la librería `cryptography`: <https://cryptography.io/en/latest/hazmat/primitives/>.
