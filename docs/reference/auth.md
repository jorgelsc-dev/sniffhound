# Auth

SniffHound usa un token de sesion corto para la UI y JWT HS256 para integraciones o pruebas automatizadas.

## Token de sesion

- se genera al arrancar;
- tiene 8 caracteres alfanumericos;
- se imprime en la terminal cuando inicia `sniffhound`.

Cabeceras aceptadas:

- `Authorization: Bearer <token>`
- `X-Access-Token: <token>`
- `?access_token=<token>`, `?token=<token>` o `?auth=<token>` para WebSocket y peticiones HTTP

Si `SNIFFHOUND_REQUIRE_AUTH=0`, la app permite acceso anonimo cuando no se envia token.

## JWT

`sniffhound.auth.generate_token()` crea JWT firmados con HS256.

Variables:

- `SNIFFHOUND_JWT_SECRET`: clave de firma
- `SNIFFHOUND_JWT_TTL`: tiempo de vida en segundos

Ejemplo:

```bash
curl -H "Authorization: Bearer TOKEN" http://127.0.0.1:45678/api/auth/session
```

## Flujo de validacion

1. `extract_token_from_header()` limpia la cabecera `Authorization`.
2. `verify_token()` compara el token de sesion o valida el JWT.
3. `authenticate_request()` devuelve el estado de autentificacion para HTTP y WebSocket.
