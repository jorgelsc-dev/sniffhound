# Quick Reference

Resumen corto del runtime real de `SniffHound`.

## Instalar

```bash
python -m pip install sniffhound
```

## Arrancar

```bash
sniffhound
SNIFFHOUND_CAPTURE_AUTO_START=0 sniffhound
SNIFFHOUND_RUNTIME_MODE=honeypot sniffhound
SNIFFHOUND_CAPTURE_INTERFACES="eth0,wlan0" sniffhound
```

## Auth

- El launcher imprime un token de sesion de 8 caracteres.
- `GET /api/auth/session` indica si la API exige auth y si la sesion ya es valida.
- Se acepta `Authorization: Bearer <token>`, `X-Access-Token` o `?access_token=` en `WS /ws/`.

Generar un JWT:

```bash
python3 - <<'PY'
from sniffhound.auth import generate_token
print(generate_token(user="operator", scope="full"))
PY
```

## Runtime API

Leer estado:

```bash
curl -H "Authorization: Bearer TOKEN" \
  http://127.0.0.1:45678/api/runtime/
```

Cambiar modo:

```bash
curl -X POST http://127.0.0.1:45678/api/runtime/ \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"mode":"honeypot"}'
```

Arrancar o parar el motor activo:

```bash
curl -X POST http://127.0.0.1:45678/api/runtime/ \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"action":"start"}'

curl -X POST http://127.0.0.1:45678/api/runtime/ \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"action":"stop"}'
```

Seleccionar interfaces:

```bash
curl -X POST http://127.0.0.1:45678/api/runtime/ \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"interfaces":["eth0","wlan0"]}'
```

## URLs utiles

- Dashboard: `http://127.0.0.1:45678/`
- Docs runtime: `http://127.0.0.1:45678/docs`
- Endpoint catalog: `http://127.0.0.1:45678/api/endpoints/`
- Dashboard snapshot: `http://127.0.0.1:45678/api/dashboard/`
- WebSocket: `ws://127.0.0.1:45678/ws/?access_token=TOKEN`

## Variables utiles

```bash
SNIFFHOUND_HOST=127.0.0.1
SNIFFHOUND_PORT=45678
SNIFFHOUND_DB_PATH=SniffHound.db
SNIFFHOUND_RUNTIME_MODE=sniffer
SNIFFHOUND_CAPTURE_AUTO_START=1
SNIFFHOUND_CAPTURE_DEMO_MODE=0
SNIFFHOUND_CAPTURE_INTERFACES=eth0,wlan0
SNIFFHOUND_PROMISCUOUS=1
SNIFFHOUND_REQUIRE_AUTH=1
SNIFFHOUND_REQUIRE_ADMIN=1
SNIFFHOUND_JWT_SECRET=change-me
SNIFFHOUND_JWT_TTL=3600
```

## Logger helper

`sniffhound.logger` es un helper de libreria, no una configuracion automatica del runtime.

```python
from sniffhound.logger import get_logger

logger = get_logger("demo", log_file="events.ndjson")
logger.info("runtime event", extra={"extra_fields": {"mode": "sniffer"}})
```

## Tests

```bash
python -m unittest discover -s tests -q
pytest tests/ -q
```

## Frontend

```bash
cd frontend
npm ci
npm run dev
npm run lint
npm run build
```
