# Secretos locales

Esta carpeta guarda `clave_maestra.key` cuando la aplicación no encuentra la variable de entorno `BOVEDA_CLAVE_MAESTRA`. La aplicación la crea sola en el primer arranque.

- Está ignorada por Git. Nunca la subas al repositorio.
- Si se pierde, los documentos cifrados no se pueden recuperar. Respáldala fuera del proyecto.
- En un servidor, usa la variable de entorno o un gestor de secretos y no dejes este archivo en disco.
