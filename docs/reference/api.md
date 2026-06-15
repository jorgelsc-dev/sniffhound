# API y WS

La superficie publica se expone desde el mismo proceso que sirve la UI. Para ver el catalogo completo y actualizado usa `GET /api/endpoints/`.

## Rutas mas usadas

| Ruta | Uso |
| --- | --- |
| `GET /docs` | Documentacion de runtime servida por la app. |
| `GET /docs.json` | Payload JSON de esa documentacion. |
| `GET /api/dashboard/` | Snapshot para la UI principal. |
| `GET /api/charts/analytics` | Datos para graficas. |
| `GET /api/map/scan` | Vista de red y mapa de trafico. |
| `POST /api/echo` | Eco de depuracion para probar POST y serializacion. |
| `GET /protocols/` | Protocolos observados. |
| `GET /targets/` | Sesiones de captura. |
| `GET|DELETE /ports/` | Paquetes capturados. |
| `GET|DELETE /banners/` | Respuestas registradas. |
| `GET /tags/` | Etiquetas de paquetes. |
| `GET /api/ip/domains/` | Dominios asociados a una IP. |
| `GET /api/ip/ttl-path/` | Estimacion de saltos para una IP. |
| `GET /api/ip/intel/` | Perfil combinado de una IP. |
| `GET|POST /api/catalog/file/banner-rules` | Archivo de reglas de banners. |
| `GET|POST /api/catalog/file/banner-requests` | Archivo de firmas de banners. |
| `GET|POST /api/catalog/file/ip-presets` | Archivo de presets de captura. |
| `GET|POST|PUT|DELETE /api/catalog/banner-rules/` | CRUD de reglas. |
| `GET|POST|PUT|DELETE /api/catalog/banner-requests/` | CRUD de firmas. |
| `GET|POST|PUT|DELETE /api/catalog/ip-presets/` | CRUD de presets. |
| `GET|POST /api/ws/*` | Acciones sobre clientes WebSocket. |
| `WS /ws/` | Canal en vivo del dashboard. |

## Flujo de autenticacion

La mayoria de las rutas de API requieren token de sesion o JWT. Usa `GET /api/auth/session` para comprobar si la peticion esta autenticada.

## Clientes en vivo

- `GET /api/ws/clients`
- `POST /api/ws/broadcast`
- `POST /api/ws/ping`
- `POST /api/ws/close`
- `GET /api/chat/messages`
- `POST /api/chat/clear`

## Notas utiles

- `GET /api/hello` devuelve version y modo activo.
- `GET /api/soc/analysis/` resume la triage SOC sobre datos recientes.
- el runtime emite eventos `packet`, `stats_update`, `runtime_mode` y mensajes de chat por WebSocket.
