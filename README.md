# Bóveda

Bóveda es una aplicación web de mensajería privada. Cada usuario le escribe a otro; el mensaje se cifra antes de guardarse y se firma con la llave del remitente. El destinatario puede comprobar que nadie lo cambió, y cualquiera puede verificar un comprobante sin tener cuenta.

Es la práctica 4 de **Seguridad en cómputo** e integra dos mecanismos criptográficos:

| Mecanismo | Algoritmo | Uso en la aplicación |
|---|---|---|
| Cifrado simétrico | AES-256-GCM | El asunto y el cuerpo de cada mensaje se guardan cifrados |
| Firma asimétrica | Ed25519 | Cada mensaje se firma al enviarlo y se puede verificar después |

Todo el código criptográfico usa la librería [cryptography](https://cryptography.io). No hay ningún algoritmo implementado a mano.

## Ejecutar en local

Necesitas Python 3.10 o superior. Está probado en Windows con Python 3.13.

**Windows (PowerShell)**

```powershell
git clone https://github.com/ProtoFurOwO/boveda.git
cd boveda
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python run.py
```

Si PowerShell bloquea la activación del entorno, ejecuta una vez `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`.

**Linux y macOS**

```bash
git clone https://github.com/ProtoFurOwO/boveda.git
cd boveda
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python run.py
```

Abre <http://127.0.0.1:5000> y crea una cuenta.

La primera vez que arranca, Bóveda genera la clave maestra en `secretos/clave_maestra.key`. Ese archivo no se sube a Git. Lee la sección [Gestión de llaves](#gestión-de-llaves) antes de usarla con datos reales.

## Cómo funciona en 30 segundos

1. **Ana** crea su cuenta. Se genera un par de llaves Ed25519. Su llave privada se guarda cifrada con su contraseña.
2. **Beto** crea otra cuenta.
3. Ana le escribe un mensaje a Beto y confirma **su contraseña**. Bóveda desbloquea su llave privada, cifra el mensaje con AES-256-GCM y lo firma con Ed25519.
4. La base de datos guarda **solo el cifrado** y la firma.
5. Beto abre el mensaje: Bóveda lo descifra y verifica la firma con la llave pública de Ana. El sello dice **Firmado**.
6. Beto descarga un **comprobante** (.json) con el texto firmado. Cualquiera puede verificarlo en *Verificar comprobante* de esta instalación sin cuenta. Si el comprobante viene de otra instalación, se verifica con `scripts/verificar_comprobante.py` y la clave pública del remitente.
7. Si alguien cambia el mensaje en la base de datos, el sello pasa a **Alterado**.
8. Si quieres, crea un **enlace público** de solo lectura para que otra persona vea el mensaje sin cuenta. Caduca en 7 días y se puede revocar.

## Recorrido de demostración

1. Crea **dos cuentas** (por ejemplo `ana` y `beto`), en dos ventanas o cerrando sesión entre una y otra.
2. Entra como `ana`, pulsa **Escribir mensaje**, elige `beto`, escribe un asunto y un texto, y confirma tu contraseña. Abre *Lo que se guarda en la base de datos*: solo se ve texto cifrado.
3. Entra como `beto`: el mensaje aparece en **Recibidos** con el sello *Firmado*. Ábrelo y descarga el **comprobante**.
4. En una ventana privada de esta misma instalación, entra a *Verificar comprobante* y sube el `.json`. Dice **Auténtico** sin pedir cuenta.
5. Simula a un atacante con la clave maestra que cambia el texto directamente en la base de datos:

   ```bash
   python scripts/manipular_mensaje.py <id-del-mensaje> llave "Mensaje cambiado"
   ```

   El id está en la URL del mensaje (`/mensajes/<id>`). Recarga la página como Beto: el sello cambia a *Alterado*.

6. Simula a un atacante sin la clave maestra, que solo corrompe el cifrado:

   ```bash
   python scripts/manipular_mensaje.py <id-del-mensaje> bytes
   ```

   AES-GCM detecta la corrupción y el mensaje ya no se puede descifrar.

7. Verifica el comprobante por consola, sin la aplicación:

   ```bash
   python scripts/verificar_comprobante.py comprobante-1a2b3c4d.json
   ```

   Devuelve `[OK]` con código de salida 0. Si editas el JSON, devuelve `[FALLO]` con código 1.

8. En el detalle del mensaje, pulsa **Crear enlace público**. Copia el enlace (se muestra una sola vez), ábrelo en una ventana privada y verás el mensaje en solo lectura. Caduca en 7 días y puedes revocarlo.

Para ver el flujo completo en consola, sin tocar tus datos reales:

```bash
python scripts/demostracion.py
```

## Compartir un mensaje

En el detalle de un mensaje, el remitente o el destinatario pueden pulsar **Crear enlace público**. Bóveda genera una URL como:

```text
http://127.0.0.1:5000/p/BPgmESoNZ3NWnPMwoZQPWfcXlbVVXYzXjhQaVMNAXgU
```

- El enlace es de **solo lectura**: muestra el asunto, el texto y el sello de firma.
- No hace falta cuenta para abrirlo. Cualquiera que tenga la URL puede leer el mensaje.
- El **token** tiene 256 bits aleatorios. En la base de datos se guarda solo su **hash SHA-256**, no el token.
- El token se muestra **una sola vez**, al crearlo. Si lo pierdes, revoca ese enlace y crea otro.
- Caduca a los **7 días** y se puede **revocar** desde el mismo panel.
- Si el mensaje se elimina, sus enlaces dejan de funcionar.
- Las respuestas de `/p/<token>` llevan `Referrer-Policy: no-referrer`, `X-Robots-Tag: noindex, nofollow` y `Cache-Control: no-store`.
- Un token inválido, caducado o revocado responde **404**, igual que uno que no existe. No hay IDs de mensaje en la URL y no se pueden listar enlaces.

### Demostración de alteración

Crea un enlace y ábrelo en una ventana privada. Luego:

```bash
# Cambia el texto con la clave maestra
python scripts/manipular_mensaje.py <id-del-mensaje> llave "La clave es 0000."

# Recarga el enlace público: sello Alterado y advertencia
```

También puedes mover el cifrado de un mensaje a otro:

```bash
python scripts/manipular_mensaje.py <id-destino> trasplantar <id-origen>
```

El enlace del destino muestra **Alterado** y no puede descifrar el contenido, porque los datos asociados de AES-GCM incluyen el remitente, el destinatario, el ID del mensaje y el campo. El mensaje original sigue válido.

Prueba también:

- cambiar un carácter del token → **404**;
- revocar el enlace y recargar → **404**;
- abrir `/mensajes/<id>` sin ser remitente ni destinatario → **404** o login (el enlace es la única vía pública).

## Inspeccionar la base de datos

Para demostrar que el mensaje se guarda cifrado y que las llaves están donde deben:

```bash
python scripts/inspeccionar_bd.py
python scripts/inspeccionar_bd.py usuarios
python scripts/inspeccionar_bd.py mensajes --completo
python scripts/inspeccionar_bd.py compartidos
python scripts/inspeccionar_bd.py buscar "CLAVE-SECRETA-4321"
python scripts/inspeccionar_bd.py esquema
```

- `resumen`: conteos de usuarios, mensajes y enlaces.
- `usuarios`: hash de contraseña, sal, llave pública y llave privada cifrada.
- `mensajes`: remitente, destinatario, asunto/cuerpo cifrados, firma y fecha.
- `compartidos`: hash del token, creador, caducidad y revocación.
- `buscar`: comprueba que una marca única no aparece en el volcado lógico de la base.
- `esquema`: columnas de las tablas.

La base por defecto es `data/boveda.db`. Si usas otra, define `BOVEDA_BASE_DATOS`. La clave maestra no está en la base y el script nunca la muestra.

Para la demo, crea un mensaje con una marca única como `CLAVE-SECRETA-4321` y ejecuta `buscar "CLAVE-SECRETA-4321"`: debe decir **“No aparece en claro”**.

## Mecanismos criptográficos

### 1. Cifrado simétrico: AES-256-GCM

El asunto y el cuerpo de cada mensaje se cifran por separado:

```
texto en claro  ──AES-256-GCM──►  base de datos   (v1:<nonce>:<cifrado>)
base de datos   ──AES-256-GCM──►  texto en claro  (descifra y comprueba)
```

- **Algoritmo:** AES con clave de 256 bits en modo GCM (NIST SP 800-38D). Cifra y autentica en una sola operación.
- **Nonce:** 96 bits aleatorios en cada cifrado.
- **Datos asociados:** cada cifrado queda atado a su remitente, su destinatario, su mensaje y su campo. Si alguien copia el cifrado a otro mensaje, el descifrado falla.
- **Código:** `boveda/criptografia/simetrico.py` y `boveda/servicios/mensajes.py`.

### 2. Firma asimétrica: Ed25519

Al registrarse, cada usuario recibe un par de llaves Ed25519. Firma los mensajes con la privada; cualquiera los verifica con la pública.

- **Qué se firma:** una representación canónica (JSON con claves ordenadas) del identificador, el remitente, el destinatario, el asunto, el cuerpo, la fecha de envío y la fecha de firma.
- **Quién puede firmar:** solo el remitente, y firmar exige confirmar su contraseña, que desbloquea la llave privada.
- **Cuándo se verifica:** cada vez que se abre el mensaje, con la clave pública registrada del remitente. No requiere contraseña.
- **Qué invalida la firma:** cualquier cambio en el contenido o en sus metadatos. Los mensajes no se editan.
- **Comprobantes:** el JSON descargable contiene el texto firmado, la firma y la clave pública del remitente. Quien lo recibe puede verificarlo con `scripts/verificar_comprobante.py`, sin acceder a la aplicación. La página *Verificar comprobante* de la app usa la clave registrada en esa instalación; para un comprobante de otra instalación, usa el script.
- **Código:** `boveda/criptografia/asimetrico.py` y `boveda/servicios/comprobantes.py`.

### Mecanismos de apoyo

- **scrypt** (RFC 7914, con N=2¹⁷, r=8, p=1, los parámetros que recomienda OWASP) para verificar contraseñas y para derivar la clave que abre la llave privada.
- **HKDF-SHA256** (RFC 5869) para derivar la clave de datos y la clave de sesión a partir de la clave maestra.

## Gestión de llaves

Cada llave tiene un lugar definido. Ninguna está escrita en el código fuente.

| Llave | Dónde vive | Cómo se protege | Quién la usa |
|---|---|---|---|
| **Clave maestra** (256 bits) | 1. Variable de entorno `BOVEDA_CLAVE_MAESTRA`<br>2. Archivo `secretos/clave_maestra.key`, fuera de Git | Nunca entra a la base de datos ni al código. El archivo solo lo puede leer tu usuario del sistema. | El servidor, al arrancar |
| **Clave de datos** | Solo en memoria | HKDF desde la clave maestra, propósito `datos-mensajes` | Cifrar y descifrar mensajes |
| **Clave de sesión** | Solo en memoria | HKDF desde la clave maestra, propósito `sesion-web` | Firmar las cookies de sesión |
| **Llave privada de firma** (por usuario) | Columna `clave_privada_cifrada` de la base de datos | AES-256-GCM con una clave derivada de tu contraseña (scrypt con sal propia). Nunca se guarda en claro. | Solo al enviar un mensaje, cuando confirmas tu contraseña |
| **Llave pública de firma** (por usuario) | Columna `clave_publica_pem` | No es secreta. Se identifica por su huella SHA-256. | Cualquiera, para verificar mensajes y comprobantes |

La clave maestra se busca primero en la variable de entorno y después en el archivo. Si no existe ninguna, se genera una en el archivo durante el primer arranque. Si la variable está definida pero no es válida, la aplicación se detiene: nunca usa otra clave en silencio.

**Recomendaciones:**

- **Desarrollo local:** deja que la aplicación genere `secretos/clave_maestra.key` y respáldalo fuera del proyecto. Si lo pierdes, los mensajes cifrados no se pueden recuperar.
- **Servidor:** genera una clave con `python scripts/generar_clave_maestra.py` y guárdala en el gestor de secretos del servicio (variables del servicio, Azure Key Vault, AWS Secrets Manager o HashiCorp Vault). No la dejes en disco.
- **Estado actual:** la página *Seguridad* muestra de dónde se cargó la clave y su huella. Nunca muestra la clave.

## Repositorio

El código está publicado en <https://github.com/ProtoFurOwO/boveda>.

Para clonarlo:

```bash
git clone https://github.com/ProtoFurOwO/boveda.git
cd boveda
```

Después instala y ejecuta con los comandos de [Ejecutar en local](#ejecutar-en-local). La app corre en `http://127.0.0.1:5000` de esa máquina.

Cada instalación tiene su propia base de datos y su propia clave maestra: un clon nuevo no ve tus mensajes. Para que otra persona use tu instancia, compártele una URL de tu servidor o de tu red. Para que verifique un comprobante emitido en tu instancia, pásale el `.json` y la clave pública del remitente; el script `verificar_comprobante.py` funciona sin tu base de datos.

Para mostrarla desde otro equipo de la misma red (por ejemplo, el del profesor):

```powershell
$env:BOVEDA_HOST = "0.0.0.0"
python run.py
```

Windows puede pedir permiso de firewall. La otra persona entra a `http://TU_IP:5000`, por ejemplo `http://192.168.1.25:5000`.

Esto es HTTP sin TLS: úsalo solo para una demostración en una red de confianza y con cuentas de prueba. Para algo que salga de la red local, pon TLS delante (Caddy, nginx) o un túnel de desarrollo (cloudflared, ngrok), y nunca con datos reales.

## Variables de entorno

| Variable | Valor por defecto | Para qué sirve |
|---|---|---|
| `BOVEDA_CLAVE_MAESTRA` | vacía | Clave maestra en base64 (32 bytes). Tiene prioridad sobre el archivo. |
| `BOVEDA_CLAVE_ARCHIVO` | `secretos/clave_maestra.key` | Ruta del archivo de clave maestra |
| `BOVEDA_BASE_DATOS` | `data/boveda.db` | Ruta de la base SQLite |
| `BOVEDA_HOST` | `127.0.0.1` | Dirección donde escucha el servidor |
| `BOVEDA_PUERTO` | `5000` | Puerto del servidor |
| `BOVEDA_COOKIES_SEGURAS` | `0` | Pon `1` cuando la app esté detrás de HTTPS |

Ejemplo en PowerShell, usando una clave nueva:

```powershell
$env:BOVEDA_CLAVE_MAESTRA = python scripts\generar_clave_maestra.py
python run.py
```

## Pruebas

```bash
pip install -r requirements-dev.txt
python -m pytest
```

Las 59 pruebas cubren las primitivas (cifrado, firma y manejo de claves), los servicios (usuarios, envío de mensajes, comprobantes, enlaces compartidos y alteraciones) y el flujo web (sesión, CSRF, cabeceras, verificación pública y enlaces).

## Estructura del proyecto

```
boveda/
  app.py                  fábrica de la aplicación Flask
  config.py               variables de entorno y rutas
  db.py                   SQLite y esquema
  criptografia/
    claves.py             clave maestra y derivación de subclaves (HKDF)
    simetrico.py          AES-256-GCM
    asimetrico.py         Ed25519 y canonización de datos firmados
    contrasenas.py        scrypt
  servicios/              lógica de negocio, sin Flask
    usuarios.py
    mensajes.py
    comprobantes.py
    compartidos.py       enlaces públicos con token, caducidad y revocación
  web/                    rutas, sesión, CSRF y cabeceras HTTP
  templates/ static/      interfaz (incluye compartido.html)
scripts/                  demostración y herramientas de consola
tests/                    pruebas automáticas
docs/criptografia.md      diseño, modelo de amenazas y decisiones
```

## Límites

Esta es una práctica académica. Para usarla en producción falta trabajo:

- El cifrado protege los mensajes en reposo. Quien tenga la clave maestra puede leerlos: no es un sistema de extremo a extremo.
- No hay HTTPS. En un servidor, pon TLS delante de la aplicación y activa `BOVEDA_COOKIES_SEGURAS=1`.
- No hay límite de intentos de inicio de sesión.
- No hay rotación de la clave maestra ni recuperación de contraseñas. Si olvidas tu contraseña, no puedes firmar.
- No hay estados de lectura ni adjuntos.
- Todos los usuarios registrados aparecen como posibles destinatarios; no hay lista de contactos.
- Un enlace compartido es un secreto portador: cualquiera que lo tenga puede leer el mensaje. Caduca a los 7 días y se puede revocar, pero si se filtra antes, hay que revocarlo.

El modelo de amenazas completo está en [docs/criptografia.md](docs/criptografia.md).

## Créditos

- Tipografía [IBM Plex](https://github.com/IBM/plex), licencia SIL Open Font License 1.1, distribuida con [@fontsource](https://fontsource.org). El texto de la licencia está en `boveda/static/fonts/`.
- Librerías: [cryptography](https://cryptography.io), [Flask](https://flask.palletsprojects.com) y [Waitress](https://docs.pylonsproject.org/projects/waitress/).
