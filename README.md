# SniffHound

`SniffHound` es un capturador y analizador de trafico en Python nativo. Usa `socket`, `threading`, `sqlite3` y `wsbuilder` para servir una UI/API local que puede operar como `sniffer` o como `honeypot`.

Sitio oficial: [https://sniffhound.jorgelsc.dev](https://sniffhound.jorgelsc.dev)<br>
Repositorio: [https://github.com/jorgelsc-dev/sniffhound](https://github.com/jorgelsc-dev/sniffhound)<br>
PyPI: `sniffhound`<br>
Comando: `sniffhound`

## Mapa rapido

`Operador -> token de sesion -> dashboard / API -> RuntimeController -> Sniffer | Honeypot -> SQLite -> charts / mapa / WebSocket`

## Lo que incluye

- Captura raw para IPv4, IPv6, ARP, TCP, UDP, ICMP y STP.
- Persistencia SQLite para sesiones, flows, packets, payloads, tags y runtime config.
- Modo `honeypot` con listeners TCP/UDP sobre puertos comunes.
- Dashboard Vue 3 + Vuetify servido por el mismo proceso.
- Autenticacion por token de sesion y JWT HS256.
- WebSocket en vivo para eventos `packet`, `stats_update`, `runtime_mode` y chat.
- Catalogos editables para reglas, probes y presets desde API o archivos JSON.

## Requisitos

- Python `3.12+`
- Linux/Unix con `AF_PACKET` para captura raw en modo `sniffer`
- privilegios de administrador o `CAP_NET_RAW` para captura live
- Node `>=22.12.0` solo si vas a trabajar en `frontend/`

## Instalacion

### Desde PyPI

```bash
python -m pip install --upgrade pip
python -m pip install sniffhound
```

### Desde el repo

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
```

## Inicio rapido

### 1. Arrancar el runtime

```bash
sniffhound
```

Notas del launcher:

- Si `45678` esta ocupado, prueba el resto del mismo bloque de 10 puertos y avisa cual usa.
- Si faltan privilegios para captura raw y corresponde elevar, intenta relanzarse con `sudo`.
- Si solo quieres abrir la UI sin autoarranque de captura, usa `SNIFFHOUND_CAPTURE_AUTO_START=0`.

Ejemplos utiles:

```bash
SNIFFHOUND_CAPTURE_AUTO_START=0 sniffhound
SNIFFHOUND_RUNTIME_MODE=honeypot sniffhound
SNIFFHOUND_CAPTURE_INTERFACES="eth0,wlan0" sniffhound
```

### 2. Copiar el token de sesion

Al arrancar, `sniffhound` imprime un token de 8 caracteres en la terminal. La UI lo pide al abrirse y lo reutiliza para HTTP y WebSocket.

### 3. Abrir la interfaz

- Dashboard: `http://127.0.0.1:45678`
- Docs runtime: `http://127.0.0.1:45678/docs`
- Catalogo de endpoints: `http://127.0.0.1:45678/api/endpoints/`

### 4. Confirmar auth y runtime

```bash
curl http://127.0.0.1:45678/api/auth/session
curl -H "Authorization: Bearer TOKEN" http://127.0.0.1:45678/api/runtime/
curl -H "Authorization: Bearer TOKEN" http://127.0.0.1:45678/api/dashboard/
```

## Modos de ejecucion

### `sniffer`

- abre un socket raw por interfaz seleccionada;
- parsea Ethernet, VLAN, IPv4, IPv6, ARP, TCP, UDP, ICMP e ICMPv6;
- registra paquetes, flows y tags en SQLite;
- emite eventos `packet` y `stats_update` por WebSocket.

### `honeypot`

- levanta listeners TCP/UDP sobre puertos conocidos;
- responde con banners y payloads predefinidos;
- guarda el trafico como sesiones `honeypot:*` en la misma base;
- escribe actividad operativa en `honeypot.log`.

### Cambio de modo

El runtime se cambia por API:

```bash
curl -X POST http://127.0.0.1:45678/api/runtime/ \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"mode":"honeypot"}'
```

Arranque/parada del motor activo:

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

## Flujo mental

1. `manage.py` selecciona puerto, imprime token y arranca el runtime.
2. `app.py` sirve la SPA, protege la API y conecta el `RuntimeController`.
3. `Sniffer` o `HoneypotEngine` generan eventos y escriben en `SniffStore`.
4. `api/dashboard`, `api/charts/analytics`, `api/map/scan` y `WS /ws/` consumen ese estado.

## Auth y acceso

- `SNIFFHOUND_REQUIRE_AUTH=1` por defecto.
- Se aceptan:
  - `Authorization: Bearer <token>`
  - `X-Access-Token: <token>`
  - `?access_token=<token>` en WebSocket
- `GET /api/auth/session` indica si la sesion esta autenticada.
- `sniffhound.auth.generate_token()` crea JWT HS256 para integraciones.
- `SNIFFHOUND_JWT_SECRET` define la clave de firma.
- `SNIFFHOUND_JWT_TTL` define el TTL en segundos.

## Superficie HTTP y WS

Rutas mas utiles:

- `GET /`
- `GET /docs`
- `GET /docs.json`
- `GET /api/auth/session`
- `GET|POST /api/runtime/`
- `GET /api/dashboard/`
- `GET /api/charts/analytics`
- `GET /api/map/scan`
- `GET /api/soc/analysis/`
- `GET /protocols/`
- `GET /targets/`
- `POST|PUT|DELETE /target/`
- `POST /target/action/`
- `GET|DELETE /ports/` y variantes por protocolo
- `GET|DELETE /banners/`
- `GET /tags/` y variantes por protocolo
- `GET /api/catalog/*`
- `POST /api/ws/broadcast`
- `POST /api/ws/ping`
- `POST /api/ws/close`
- `GET /api/chat/messages`
- `POST /api/chat/clear`
- `WS /ws/`

## Configuracion util

Variables practicas del runtime:

- `SNIFFHOUND_HOST`
- `SNIFFHOUND_PORT`
- `SNIFFHOUND_DB_PATH`
- `SNIFFHOUND_RUNTIME_MODE`
- `SNIFFHOUND_CAPTURE_AUTO_START`
- `SNIFFHOUND_CAPTURE_DEMO_MODE`
- `SNIFFHOUND_CAPTURE_INTERFACES`
- `SNIFFHOUND_PROMISCUOUS`
- `SNIFFHOUND_CAPTURE_BUFFER_BYTES`
- `SNIFFHOUND_POLL_TIMEOUT`
- `SNIFFHOUND_REQUIRE_AUTH`
- `SNIFFHOUND_REQUIRE_ADMIN`
- `SNIFFHOUND_JWT_SECRET`
- `SNIFFHOUND_JWT_TTL`
- `SNIFFHOUND_FRONTEND_DIST`

## Componentes del repo

- `sniffhound/manage.py`: launcher, elevacion opcional y consola interactiva.
- `sniffhound/app.py`: SPA, API, WebSocket y runtime controller.
- `sniffhound/sniffer.py`: captura raw y parseo de paquetes.
- `sniffhound/honeypot.py`: listeners emulados y registro de trafico activo.
- `sniffhound/store.py`: esquema SQLite y snapshots de dashboard.
- `sniffhound/auth.py`: token de sesion y JWT HS256.
- `sniffhound/logger.py`: helper NDJSON para integraciones y pruebas.
- `frontend/`: SPA Vue 3 + Vuetify.

## Logging y datos

- La base por defecto es `SniffHound.db`.
- El modo honeypot escribe rotacion local en `honeypot.log`.
- `sniffhound.logger` existe como helper de libreria; no esta cableado automaticamente al arranque del runtime principal.

## Desarrollo y validacion

Backend:

```bash
python -m sniffhound.manage
```

Frontend:

```bash
cd frontend
npm ci
npm run dev
```

Checks:

```bash
python -m unittest discover -s tests -q
pytest tests/ -q
```

Frontend:

```bash
cd frontend
npm run lint
npm run build
```

## Documentacion

- Sitio publico MkDocs: [https://sniffhound.jorgelsc.dev/](https://sniffhound.jorgelsc.dev/)
- Fuente del sitio: `docs/` + `mkdocs.yml`
- Dominio custom: `docs/CNAME`
- Redirecciones legacy: `docs/404.html`

Build y preview local:

```bash
python -m pip install -r requirements-docs.txt
mkdocs serve
mkdocs build --strict
```

- Resumen rapido: [QUICKREF.md](QUICKREF.md)
- Arquitectura: [ARCHITECTURE.md](ARCHITECTURE.md)
- Ejemplos: [EXAMPLES.md](EXAMPLES.md)

## Contribucion y soporte

- Mantiene intacta la restriccion de captura nativa sin dependencias de parseo de terceros.
- Actualiza docs cuando cambie UI, API o esquema.
- La documentacion publica se construye con MkDocs Material desde `docs/`.
- Reporta vulnerabilidades por canal privado.
- Soporte y notas adicionales: `SUPPORT.md`
