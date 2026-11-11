# Bóveda

Bóveda es una aplicación web para guardar documentos sensibles. Cada documento se cifra antes de llegar a la base de datos y puede firmarse con una llave digital para demostrar después que no cambió.

Es la práctica 4 de **Seguridad en cómputo** e integra dos mecanismos criptográficos:

| Mecanismo | Algoritmo | Uso en la aplicación |
|---|---|---|
| Cifrado simétrico | AES-256-GCM | El título y el texto de cada documento se guardan cifrados |
| Firma asimétrica | Ed25519 | Cada usuario firma sus documentos y puede descargar un certificado que cualquiera verifica |

Todo el código criptográfico usa la librería [cryptography](https://cryptography.io). No hay ningún algoritmo implementado a mano.

## Ejecutar en local

Necesitas Python 3.10 o superior. Está probado en Windows con Python 3.13.

**Windows (PowerShell)**

```powershell
git clone https://github.com/TU_USUARIO/boveda.git
cd boveda
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python run.py
```

Si PowerShell bloquea la activación del entorno, ejecuta una vez `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`.

**Linux y macOS**

```bash
git clone https://github.com/TU_USUARIO/boveda.git
cd boveda
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python run.py
```

Abre <http://127.0.0.1:5000>, crea una cuenta y empieza.

La primera vez que arranca, Bóveda genera la clave maestra en `secretos/clave_maestra.key`. Ese archivo no se sube a Git. Lee la sección [Gestión de llaves](#gestión-de-llaves) antes de usarla con datos reales.

## Recorrido de demostración

1. **Crea una cuenta.** Al registrarte se genera tu par de llaves Ed25519. La llave privada queda cifrada con tu contraseña.
2. **Crea un documento.** En la vista del documento, abre *Lo que se guarda en la base de datos*: solo se ve texto cifrado.
3. **Firma el documento** con tu contraseña. El sello pasa a *Firmado*.
4. **Descarga el certificado** (.json) y verifícalo en *Verificar certificado*. No necesitas cuenta para hacerlo.
5. **Simula un atacante** que tiene la clave maestra y cambia el texto directamente en la base de datos:

   ```bash
   python scripts/manipular_documento.py <id-del-documento> llave "Texto cambiado"
   ```

   Recarga la página. El sello cambia a *Alterado*: AES-GCM no detecta el cambio porque lo cifró quien tenía la clave, pero la firma ya no coincide.

6. **Simula un atacante sin la clave maestra**, que solo corrompe el cifrado:

   ```bash
   python scripts/manipular_documento.py <id-del-documento> bytes
   ```

   AES-GCM detecta la corrupción y el contenido ya no se puede descifrar.

7. **Verifica el certificado sin la aplicación.** Usa el archivo que descargaste, por ejemplo `certificado-1a2b3c4d.json`:

   ```bash
   python scripts/verificar_certificado.py certificado-1a2b3c4d.json
   ```

   Devuelve `[OK]` con código de salida 0. Si editas el JSON, devuelve `[FALLO]` con código 1.

Para ver el flujo completo en consola, sin tocar tus datos reales:

```bash
python scripts/demostracion.py
```

## Mecanismos criptográficos

### 1. Cifrado simétrico: AES-256-GCM

El título y el contenido de cada documento se cifran por separado:

```
texto en claro  ──AES-256-GCM──►  base de datos   (v1:<nonce>:<cifrado>)
base de datos   ──AES-256-GCM──►  texto en claro  (descifra y comprueba)
```

- **Algoritmo:** AES con clave de 256 bits en modo GCM (NIST SP 800-38D). Cifra y autentica en una sola operación.
- **Nonce:** 96 bits aleatorios en cada cifrado.
- **Datos asociados:** cada cifrado queda atado a su usuario, su documento y su campo. Si alguien copia el cifrado de un documento a otro, el descifrado falla.
- **Código:** `boveda/criptografia/simetrico.py` y `boveda/servicios/documentos.py`.

### 2. Firma asimétrica: Ed25519

Al registrarse, cada usuario recibe un par de llaves Ed25519. Firma sus documentos con la privada y cualquiera los verifica con la pública.

- **Qué se firma:** una representación canónica (JSON con claves ordenadas) del identificador, el autor, el título, el contenido, la fecha de creación y la fecha de firma.
- **Quién puede firmar:** solo el autor, y firmar exige confirmar su contraseña, que desbloquea la llave privada.
- **Cuándo se verifica:** cada vez que se muestra el documento, con la clave pública registrada. No requiere contraseña.
- **Qué invalida la firma:** cualquier cambio en el contenido o en sus metadatos. Editar un documento quita la firma hasta que se vuelve a firmar.
- **Certificados:** el JSON descargable contiene el texto firmado, la firma y la clave pública del autor. Quien lo recibe puede verificarlo con `scripts/verificar_certificado.py`, sin acceder a la aplicación.
- **Código:** `boveda/criptografia/asimetrico.py` y `boveda/servicios/certificados.py`.

### Mecanismos de apoyo

- **scrypt** (RFC 7914, con N=2¹⁷, r=8, p=1, los parámetros que recomienda OWASP) para verificar contraseñas y para derivar la clave que abre la llave privada.
- **HKDF-SHA256** (RFC 5869) para derivar la clave de datos y la clave de sesión a partir de la clave maestra.

## Gestión de llaves

Cada llave tiene un lugar definido. Ninguna está escrita en el código fuente.

| Llave | Dónde vive | Cómo se protege | Quién la usa |
|---|---|---|---|
| **Clave maestra** (256 bits) | 1. Variable de entorno `BOVEDA_CLAVE_MAESTRA`<br>2. Archivo `secretos/clave_maestra.key`, fuera de Git | Nunca entra a la base de datos ni al código. El archivo solo lo puede leer tu usuario del sistema. | El servidor, al arrancar |
| **Clave de datos** | Solo en memoria | HKDF desde la clave maestra, propósito `datos-documentos` | Cifrar y descifrar documentos |
| **Clave de sesión** | Solo en memoria | HKDF desde la clave maestra, propósito `sesion-web` | Firmar las cookies de sesión |
| **Llave privada de firma** (por usuario) | Columna `clave_privada_cifrada` de la base de datos | AES-256-GCM con una clave derivada de tu contraseña (scrypt con sal propia). Nunca se guarda en claro. | Solo al firmar, cuando confirmas tu contraseña |
| **Llave pública de firma** (por usuario) | Columna `clave_publica_pem` | No es secreta. Se identifica por su huella SHA-256. | Cualquiera, para verificar firmas y certificados |

La clave maestra se busca primero en la variable de entorno y después en el archivo. Si no existe ninguna, se genera una en el archivo durante el primer arranque. Si la variable está definida pero no es válida, la aplicación se detiene: nunca usa otra clave en silencio.

**Recomendaciones:**

- **Desarrollo local:** deja que la aplicación genere `secretos/clave_maestra.key` y respáldalo fuera del proyecto. Si lo pierdes, los documentos cifrados no se pueden recuperar.
- **Servidor:** genera una clave con `python scripts/generar_clave_maestra.py` y guárdala en el gestor de secretos del servicio (variables del servicio, Azure Key Vault, AWS Secrets Manager o HashiCorp Vault). No la dejes en disco.
- **Estado actual:** la página *Seguridad* muestra de dónde se cargó la clave y su huella. Nunca muestra la clave.

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

Las 44 pruebas cubren las primitivas (cifrado, firma y manejo de claves), los servicios (usuarios, documentos, certificados y alteraciones) y el flujo web (sesión, CSRF, cabeceras y verificación pública).

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
    documentos.py
    certificados.py
  web/                    rutas, sesión, CSRF y cabeceras HTTP
  templates/ static/      interfaz
scripts/                  demostración y herramientas de consola
tests/                    pruebas automáticas
docs/criptografia.md      diseño, modelo de amenazas y decisiones
```

## Límites

Esta es una práctica académica. Para usarla en producción falta trabajo:

- No hay HTTPS. En un servidor, pon TLS delante de la aplicación y activa `BOVEDA_COOKIES_SEGURAS=1`.
- No hay límite de intentos de inicio de sesión.
- No hay rotación de la clave maestra ni recuperación de contraseñas. Si olvidas tu contraseña, no puedes firmar.
- Quien tenga la clave maestra puede leer los documentos. El modelo de amenazas completo está en [docs/criptografia.md](docs/criptografia.md).

## Créditos

- Tipografía [IBM Plex](https://github.com/IBM/plex), licencia SIL Open Font License 1.1, distribuida con [@fontsource](https://fontsource.org). El texto de la licencia está en `boveda/static/fonts/`.
- Librerías: [cryptography](https://cryptography.io), [Flask](https://flask.palletsprojects.com) y [Waitress](https://docs.pylonsproject.org/projects/waitress/).
