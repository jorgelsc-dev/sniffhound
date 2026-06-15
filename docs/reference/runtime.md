# Runtime

## Variables clave

| Variable | Default | Uso |
| --- | --- | --- |
| `SNIFFHOUND_HOST` | `127.0.0.1` | Host de escucha de la app. |
| `SNIFFHOUND_PORT` | `45678` | Puerto HTTP principal. |
| `SNIFFHOUND_DB_PATH` | `SniffHound.db` | Ruta de SQLite. |
| `SNIFFHOUND_RUNTIME_MODE` | `sniffer` | Motor inicial. |
| `SNIFFHOUND_CAPTURE_AUTO_START` | `1` | Arranque automatico del motor. |
| `SNIFFHOUND_CAPTURE_DEMO_MODE` | `0` | Relaja el relanzado con privilegios. |
| `SNIFFHOUND_CAPTURE_INTERFACES` | vacio | Interfaces activas para `sniffer`. |
| `SNIFFHOUND_PROMISCUOUS` | `1` | Modo promiscuo en captura raw. |
| `SNIFFHOUND_SNAPLEN` | `65535` | Tamano maximo del paquete capturado. |
| `SNIFFHOUND_POLL_TIMEOUT` | `0.5` | Espera de polling en captura. |
| `SNIFFHOUND_CAPTURE_BUFFER_BYTES` | `524288` | Buffer de captura. |
| `SNIFFHOUND_REQUIRE_ADMIN` | auto | Fuerza o desactiva el relanzado con `sudo`. |
| `SNIFFHOUND_FRONTEND_DIST` | auto | Sobrescribe el directorio compilado de la UI. |

## API de runtime

`GET /api/runtime/` devuelve un snapshot con el modo activo, los motores soportados y el estado de `sniffer` y `honeypot`.

`POST /api/runtime/` acepta combinaciones de estos campos:

- `mode`: `sniffer` o `honeypot`
- `action`: `start` o `stop`
- `interface`, `interfaces`, `sniffer_interface` o `sniffer_interfaces`

Ejemplos:

```bash
curl -H "Authorization: Bearer TOKEN" http://127.0.0.1:45678/api/runtime/

curl -X POST http://127.0.0.1:45678/api/runtime/ \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"action":"start"}'

curl -X POST http://127.0.0.1:45678/api/runtime/ \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"mode":"honeypot","interfaces":["eth0"]}'
```

## Notas

- si `SNIFFHOUND_CAPTURE_AUTO_START=0`, `start` solo devuelve estado;
- si cambias `mode`, el runtime detiene el motor anterior antes de activar el nuevo;
- `interfaces` se persistira en `runtime_config` para `sniffer`.
