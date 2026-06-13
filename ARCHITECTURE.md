# Arquitectura

`SniffHound` se organiza alrededor de una superficie HTTP/WebSocket pequena, dos motores (`sniffer` y `honeypot`) y una base SQLite compartida.

## Vista general

```text
Operador / navegador
        |
        v
  sniffhound.manage
        |
        v
  sniffhound.app (App, API, WS, auth, SPA)
        |
        +--> RuntimeController --> Sniffer
        |                         HoneypotEngine
        |
        +--> SniffStore (SQLite)
        |
        +--> frontend/dist + WebSocketHub
```

## Arranque

1. `sniffhound.manage` resuelve `HOST` y `PORT`.
2. Si el puerto pedido esta ocupado, busca otro libre en el mismo bloque de 10 puertos.
3. Si `CAPTURE_AUTO_START=1` y faltan privilegios, intenta relanzarse con `sudo` salvo que `SNIFFHOUND_REQUIRE_ADMIN=0` o `CAPTURE_DEMO_MODE=1`.
4. Imprime el token de sesion, arranca la consola interactiva y llama a `app.run(...)`.
5. `bootstrap_capture()` arranca el motor activo si el autoarranque sigue habilitado.

## `sniffhound.app`

Responsabilidades:

- crear `App()` de `wsbuilder`;
- servir la SPA y los assets estaticos;
- exponer `/docs` y `/docs.json`;
- proteger la API y `WS /ws/` con auth;
- coordinar `Sniffer`, `HoneypotEngine`, `SniffStore` y `WebSocketHub`;
- persistir modo de runtime e interfaces seleccionadas.

Piezas clave:

- `RuntimeController`: decide si el motor activo es `sniffer` o `honeypot`.
- `WebSocketHub`: registra clientes, emite eventos y gestiona `ping` / `close`.
- `_apply_api_auth_guards()`: envuelve todas las rutas API salvo `GET /api/auth/session`.

## `sniffhound.sniffer`

Responsabilidades:

- descubrir interfaces disponibles;
- abrir un socket raw por interfaz activa;
- parsear Ethernet, VLAN, IPv4, IPv6, ARP, TCP, UDP, ICMP, ICMPv6 y STP;
- actualizar contadores de captura;
- emitir eventos `packet` y `stats_update`;
- escribir paquetes y flows en SQLite.

Modelo:

- un hilo por interfaz;
- `RLock` para estado y contadores;
- `snapshot()` entrega estado utilizable por UI y API.

## `sniffhound.honeypot`

Responsabilidades:

- abrir listeners TCP/UDP en puertos comunes;
- responder con banners y payloads predefinidos;
- registrar sesiones como trafico `honeypot`;
- escribir actividad operativa en `honeypot.log`.

Detalles utiles:

- reutiliza `SniffStore`;
- marca filas con interfaces `honeypot` o `honeypot:<port>`;
- permite estudiar el mismo dashboard con datos pasivos o activos.

## `sniffhound.store`

Es la fuente de verdad local.

Tablas principales:

- `sessions`
- `flows`
- `packets`
- `payloads`
- `tags`
- `rulesets`
- `runtime_config`

Funciones practicas:

- `dashboard_snapshot()`
- `analytics_snapshot()`
- `map_snapshot()`
- `soc_analysis_snapshot()`
- `endpoint_catalog()`

La conexion usa:

- `journal_mode=WAL`
- `synchronous=NORMAL`
- `foreign_keys=ON`
- `busy_timeout=5000`

## Auth

`sniffhound.auth` mezcla dos mecanismos:

- token de sesion de 8 caracteres generado al arranque;
- JWT HS256 creado con `generate_token()`.

Entradas aceptadas:

- `Authorization: Bearer ...`
- `X-Access-Token`
- `access_token`, `token` o `auth` en query string

Efectos:

- si `SNIFFHOUND_REQUIRE_AUTH=1`, todas las rutas API protegidas devuelven `401` sin token valido;
- `WS /ws/` se cierra con codigo `4401` cuando la autenticacion falla;
- `GET /api/auth/session` queda abierto para que la UI sepa si debe pedir token.

## Frontend

La SPA:

- consulta `/api/auth/session` para validar el token;
- lee `/api/runtime/` para modo e interfaces;
- consume `/api/dashboard/`, `/api/charts/analytics`, `/api/map/scan` y `/api/endpoints/`;
- abre `WS /ws/?access_token=...` para eventos live;
- actualiza tablas y vistas en respuesta a `packet`, `stats_update`, `runtime_mode` y `chat_message`.

## Rutas mas importantes

- `GET /`
- `GET /docs`
- `GET /docs.json`
- `GET /api/auth/session`
- `GET|POST /api/runtime/`
- `GET /api/dashboard/`
- `GET /api/soc/analysis/`
- `GET|DELETE /ports/` y variantes
- `GET|DELETE /banners/`
- `GET /tags/`
- `GET|POST /api/catalog/*`
- `WS /ws/`

## Apagado

`shutdown_capture()`:

- detiene el motor activo;
- intenta detener tambien `sniffer` y `honeypot`;
- cierra WebSocketHub;
- cierra SQLite.

Eso deja el runtime limpio cuando terminas la sesion o interrumpes con `Ctrl+C`.
