# SniffHound Architecture Guide

This document provides a deep dive into SniffHound's architecture, modules, and design patterns.

---

## System Overview

```
┌─────────────────────────────────────────────────────┐
│          Frontend (Vue 3 + Vuetify SPA)             │
│    Dashboard, Views, State Management               │
└─────────────────────────┬───────────────────────────┘
                          │ HTTP/WebSocket
                          ▼
┌─────────────────────────────────────────────────────┐
│  wsbuilder App Server (app.py)                      │
│  ├─ WebSocketHub (broadcast)                        │
│  ├─ REST API routes (/api/*)                        │
│  ├─ JWT authentication middleware                   │
│  └─ Event orchestration                             │
└──────────────┬──────────────────────────────────────┘
               │
    ┌──────────┼──────────┐
    │          │          │
    ▼          ▼          ▼
┌────────┬──────────┬───────────────┐
│Sniffer │ Honeypot │ NDJSON Logger │
│        │ Engine   │               │
│(threads)          │ (structured   │
└────────┴──────────┤  logs)        │
    │               │               │
    │   ┌───────────┴───────────┐   │
    │   │                       │   │
    ▼   ▼                       ▼   ▼
┌─────────────────────────────────────────┐
│  SniffStore (SQLite + RLock)            │
│  ├─ Packets table (2000 max)            │
│  ├─ Sessions table                      │
│  ├─ Rulesets & classifications          │
│  └─ Runtime config                      │
└─────────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────────┐
│  SniffHound.db (SQLite file)            │
│  Persistent packet & metadata storage   │
└─────────────────────────────────────────┘
```

---

## Core Modules

### 1. **app.py** - Server Orchestrator

**Responsibilities:**
- wsbuilder HTTP server setup and routing
- WebSocket hub management
- REST API endpoint definitions
- JWT authentication middleware
- Frontend static file serving
- Runtime mode switching (sniffer/honeypot)

**Key Classes:**
```python
WebSocketHub          # Manages connected clients, broadcasts
RuntimeController     # Switches between sniffer/honeypot modes
```

**Key Routes:**
- `GET /` - Dashboard frontend
- `GET /api/dashboard/` - Current snapshot
- `GET /api/endpoints/` - Endpoint catalog
- `POST /api/capture/start|stop` - Capture control
- `WS /ws/live` - Live event stream

**Auth Integration:**
```python
from sniffhound.auth import authenticate_request, extract_token_from_header

@app.view('/api/protected/', methods=('GET',))
def protected_endpoint(request):
    token = extract_token_from_header(request.headers.get('Authorization'))
    is_auth, user_info = authenticate_request(token)
    if not is_auth:
        return Response(status=401, body=b'Unauthorized')
    # ... proceed
```

---

### 2. **sniffer.py** - Packet Capture Engine

**Responsibilities:**
- Spawn worker threads per interface
- Raw socket binding and packet reception
- Binary frame parsing (Ethernet → IP → TCP/UDP/ICMP)
- MAC/IP extraction and flow tracking
- Thread-safe state management

**Key Classes:**
```python
CaptureState          # @dataclass - running, packets_seen, errors
Sniffer               # Main capture orchestrator
```

**Thread Model:**
```
Main Thread (start())
    ├── Worker Thread (eth0) → socket.recvfrom() loop
    ├── Worker Thread (eth1) → socket.recvfrom() loop
    └── Worker Thread (lo)   → socket.recvfrom() loop
```

**Packet Parsing Pipeline:**
```
Raw bytes (AFPacket)
    ↓
Ethernet frame parsing (14 bytes)
    ├─ Destination MAC (6)
    ├─ Source MAC (6)
    └─ EtherType (2)
    ↓
EtherType routing:
    ├─ 0x0800 → IPv4
    ├─ 0x86DD → IPv6
    └─ 0x0806 → ARP
    ↓
IP parsing (IPv4: 20+ bytes, IPv6: 40 bytes)
    ├─ TTL/Hop Limit
    ├─ Protocol (TCP=6, UDP=17, ICMP=1)
    └─ Source/Dest IPs
    ↓
Protocol parsing:
    ├─ TCP: Flags, ports, payload
    ├─ UDP: Ports, payload
    └─ ICMP: Type, code
    ↓
Store in SQLite
```

**Thread Safety:**
```python
self._state_lock = threading.RLock()  # Protects state mutations

with self._state_lock:
    self.state.packets_seen += 1
    self.state.last_packet_at = utc_now()
```

---

### 3. **auth.py** - JWT Authentication

**Responsibilities:**
- JWT token generation and verification
- HMAC-SHA256 signing
- Token expiry validation
- Request authentication checks

**Algorithm:** HS256 (HMAC-SHA256)

**Token Structure:**
```
Header: { "alg": "HS256", "typ": "JWT" }
Payload: { 
    "user": "admin",
    "iat": 1717675200,      # Issued at
    "exp": 1717761600,      # Expiry (default: +24h)
    ... custom claims ...
}
Signature: HMAC-SHA256(header.payload, secret_key)
```

**Example Usage:**
```python
from sniffhound.auth import generate_token, authenticate_request, extract_token_from_header

# Generate
token = generate_token(user="admin", scope="read:packets,write:capture")

# Authenticate
auth_header = "Bearer " + token
extracted = extract_token_from_header(auth_header)
is_valid, user_info = authenticate_request(extracted)

if is_valid:
    print(f"User: {user_info['user']}")
    print(f"Claims: {user_info['claims']}")
```

**Security Considerations:**
- Secret key generated from `SNIFFHOUND_SECRET_KEY` env var
- Fallback to hostname SHA256 hash (not secure for prod)
- Always use explicit secret in production
- Token expiry checked on every decode

---

### 4. **logger.py** - NDJSON Logging System

**Responsibilities:**
- Structured logging in NDJSON format
- Thread-safe file I/O with RLock
- Custom formatters for JSON serialization
- Per-module logger creation

**Features:**
```python
NDJsonFormatter       # Converts LogRecord → JSON
NDJsonHandler         # Writes to file with RLock
LoggerContext         # Temporary level changes
```

**Log Entry Structure:**
```json
{
  "timestamp": "2026-06-06T12:34:56.789Z",
  "level": "INFO",
  "logger": "sniffhound.capture",
  "message": "Starting packet capture",
  "module": "sniffer",
  "function": "_capture_worker",
  "line": 156,
  "exception": null  // only if error
}
```

**Thread Safety:**
```python
with self._lock:  # RLock prevents simultaneous writes
    file = self._get_file()
    file.write(msg + "\n")
    file.flush()
```

**Integration Points:**
```python
# In sniffer.py
from sniffhound.logger import get_capture_logger
logger = get_capture_logger()
logger.info("Capture started", extra={"interface": "eth0"})

# In app.py (requests)
from sniffhound.logger import get_request_logger
logger = get_request_logger()
logger.info("API call", extra={"method": "GET", "path": "/api/packets/"})
```

---

### 5. **store.py** - SQLite Persistence

**Responsibilities:**
- Database schema creation and management
- Thread-safe CRUD operations with RLock
- Table trimming (size limits)
- Query snapshots for dashboard/API

**Schema (simplified):**
```sql
CREATE TABLE sessions (
    id INTEGER PRIMARY KEY,
    flow_key TEXT UNIQUE,
    proto TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    packets_count INTEGER,
    bytes_total INTEGER,
    created_at TEXT,
    updated_at TEXT,
    FOREIGN KEY(id) REFERENCES packets(session_id)
);

CREATE TABLE packets (
    id INTEGER PRIMARY KEY,
    session_id INTEGER,
    eth_src TEXT,
    eth_dst TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    proto TEXT,
    src_port INTEGER,
    dst_port INTEGER,
    tcp_flags TEXT,
    payload_text TEXT,
    payload_hex TEXT,
    raw_packet BLOB,  -- Stored as hex string
    created_at TEXT,
    FOREIGN KEY(session_id) REFERENCES sessions(id)
);

CREATE TABLE rulesets (
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE,
    rules JSON,
    active INTEGER DEFAULT 1
);
```

**Thread Safety:**
```python
self._lock = threading.RLock()
with self._lock:
    conn = sqlite3.connect(self._db_path, check_same_thread=False)
    # SQLite WAL mode + RLock allows safe concurrent reads
```

**Size Limits:**
```python
PACKET_TABLE_LIMIT = 2000      # Max packets before trim
PAYLOAD_TABLE_LIMIT = 2000     # Max payloads before trim
trim_oversized_tables()        # Called every 50 packets
```

---

### 6. **honeypot.py** - Honeypot Engine

**Responsibilities:**
- Listen for probe requests on common ports
- Simulate service responses
- Log suspicious activity
- Thread-based port listeners

**Supported Ports:**
```python
HONEYPOT_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
}
```

---

### 7. **settings.py** - Configuration Management

**Loading Order:**
```python
Environment Variables
    ↓
  _env("KEY", "default")
    ↓
Converted (int/bool/etc)
    ↓
Module-level Constants
```

**Configuration Groups:**
```python
# Server
HOST, PORT, DB_PATH, DEBUG, RUNTIME_MODE

# Capture
CAPTURE_AUTO_START, CAPTURE_INTERFACES, CAPTURE_PROMISCUOUS,
CAPTURE_SNAPLEN, CAPTURE_POLL_TIMEOUT, CAPTURE_BUFFER_BYTES

# Security
SNIFFHOUND_SECRET_KEY, SNIFFHOUND_TOKEN_EXPIRY_HOURS,
SNIFFHOUND_REQUIRE_AUTH

# Logging
SNIFFHOUND_LOG_FILE, SNIFFHOUND_LOG_LEVEL
```

---

### 8. **utils.py** - Utility Functions

**Categories:**
```python
# Binary/Hex conversion
bytes_to_hex_preview()         # b"\x00\x01" → "0001..."
bytes_to_text_preview()        # b"Hello" → "Hello"
format_mac()                   # bytes → "AA:BB:CC:DD:EE:FF"

# Parsing & Validation
safe_int()                     # Fallback parsing
safe_float()                   # Fallback parsing
clamp_int()                    # Min/max bounds
normalize_text()               # Remove unsafe chars
normalize_protocol_name()      # TCP → tcp

# Flow tracking
stable_flow_key()              # Deterministic 5-tuple hash
local_ip_candidates()          # Detect local IPs

# Serialization
json_dumps()                   # Consistent JSON output
utc_now()                      # ISO 8601 timestamps
```

---

### 9. **rulesets.py** - Packet Classification

**Responsibilities:**
- Pattern matching on payloads
- Rule evaluation
- Tag/category assignment

**Default Rules:**
```python
{
    "http": { pattern: "GET|POST|PUT", field: "payload_text" },
    "ssh": { pattern: "SSH-2.0", field: "payload_text" },
    "dns": { proto: "udp", port: 53 },
    "tls": { pattern: b"\x16\x03", field: "raw_packet" },
}
```

---

## Design Patterns

### 1. **Thread-Safe Shared State**
```python
class Sniffer:
    def __init__(self):
        self._state_lock = threading.RLock()
        self.state = CaptureState()
    
    def _touch_packet(self, packet):
        with self._state_lock:  # Acquire lock
            self.state.packets_seen += 1  # Modify
            self.state.last_packet_at = utc_now()
        # Lock released
```

### 2. **Graceful Degradation**
```python
def _capture_worker(self, interface):
    try:
        sock = socket.socket(...)  # Raw socket
    except PermissionError:
        self._set_error(interface, "No permission")
        return  # Fail gracefully, skip this interface
    except Exception:
        self._set_error(interface, "Socket unavailable")
        return  # Non-fatal, continue with other interfaces
```

### 3. **Event Broadcasting**
```python
class WebSocketHub:
    def broadcast(self, payload: dict):
        message = json_dumps(payload)
        for client in self._clients.values():
            ws.send_text(message)  # All clients get update
```

### 4. **Factory Pattern**
```python
def _resolve_frontend_dist_dir() -> Path:
    candidates = [override, SOURCE, PACKAGE]
    for candidate in candidates:
        if candidate.exists():
            return candidate  # Return first valid
    return candidates[0]
```

### 5. **Type Hints (PEP 604)**
```python
def parse_packet(self, data: bytes, *, interface: str = "") -> dict | None:
    # Modern Python 3.10+ union syntax
    # Old: Optional[dict] = None
    # New: dict | None
```

---

## Request/Response Flow

### Packet Capture Flow

```
Network Interface
    ↓
Worker Thread receives raw bytes
    ↓
_capture_worker() reads socket
    ↓
parse_packet() decodes binary frame
    ↓
_store_packet() registers in database
    ↓
_touch_packet() updates statistics
    ↓
_broadcast_packet() sends WebSocket event
    ↓
Frontend receives real-time update
```

### API Request Flow

```
Client sends HTTP request with Authorization header
    ↓
app.py route handler
    ↓
extract_token_from_header() parses "Bearer TOKEN"
    ↓
authenticate_request() verifies JWT signature + expiry
    ↓
If valid: process request → return data
If invalid: return 401 Unauthorized
```

---

## Performance Considerations

### Packet Processing Throughput

- **Typical:** 100-500 packets/second
- **With trimming:** every 50 packets → 2000 packet limit
- **Bottleneck:** SQLite writes (not network I/O)

### Memory Usage

- **Sniffer threads:** ~5MB each
- **WebSocket clients:** ~1MB per connection
- **SQLite buffer:** ~10MB (configurable)

### Optimization Tips

1. **Increase capture buffer:**
   ```bash
   SNIFFHOUND_CAPTURE_BUFFER_BYTES=1048576  # 1MB
   ```

2. **Reduce WebSocket throttle** (frontend):
   ```javascript
   WS_REFRESH_THROTTLE_MS = 500  // From 800ms
   ```

3. **Use PostgreSQL for scale** (future):
   - Replaces SQLite
   - Multi-writer support
   - ColumnStore for analytics

---

## Security Architecture

### Authentication Flow

```
┌─────────────┐
│   Client    │
└──────┬──────┘
       │ 1. Request token with credentials
       ▼
┌─────────────────────────────────────┐
│   /api/token endpoint               │
│   Validates credentials (basic auth)│
│   Generates JWT                     │
└──────┬──────────────────────────────┘
       │ 2. Returns JWT token
       ▼
┌─────────────┐
│   Client    │ Stores token in localStorage
└──────┬──────┘
       │ 3. Includes in Authorization header
       ▼
┌─────────────────────────────────────┐
│   Protected API endpoint            │
│   Validates JWT (signature + exp)   │
│   Returns data                      │
└─────────────────────────────────────┘
```

### Data Protection

- **Payloads:** Stored as hex in SQLite (encrypted by filesystem)
- **Credentials:** Should NOT be captured (future: payload masking)
- **Log files:** NDJSON format (configurable path, handle permissions)

---

## Testing Strategy

### Unit Tests
```
- Utility functions (bytes_to_hex, safe_int, etc.)
- Auth logic (JWT encode/decode, signature verification)
- Logger output format validation
- Settings parsing
```

### Integration Tests
```
- Database operations (register_packet, queries)
- Concurrent packet registration
- WebSocket broadcasting
- API endpoint responses
```

### Security Tests
```
- No hardcoded credentials
- JWT signature validation
- Token expiry enforcement
- HTTPS headers (when applicable)
```

### Load Tests (manual)
```bash
# Generate synthetic packets
while true; do
    curl -H "Authorization: Bearer $TOKEN" \
      http://localhost:45678/api/packets/
    sleep 0.1
done
```

---

## Future Roadmap

1. **PostgreSQL Support**
   - Replace SQLite for high-throughput deployments
   - Multi-tenant isolation
   - Advanced querying/analytics

2. **RBAC (Role-Based Access Control)**
   - Admin, read-only, write roles
   - Per-interface permissions
   - API key management UI

3. **Export Formats**
   - PCAP format
   - JSON bulk export
   - CSV summaries

4. **Alerting**
   - Rule-based alerts
   - Email/Slack notifications
   - Event correlation (CEP)

5. **Browser Extension**
   - Capture from browser context
   - CORS proxy capture
   - Page analytics integration

---

## References

- [Python socket module](https://docs.python.org/3/library/socket.html)
- [RFC 791 - IPv4](https://tools.ietf.org/html/rfc791)
- [RFC 2119 - Keywords](https://tools.ietf.org/html/rfc2119)
- [JWT RFC 7519](https://tools.ietf.org/html/rfc7519)
- [NDJSON Format](http://ndjson.org/)
