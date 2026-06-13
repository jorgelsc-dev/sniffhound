# SniffHound

SniffHound is a **native Python network sniffer** built on top of `socket`, `threading`, `sqlite3`, and straightforward arithmetic and byte handling. It avoids third-party packet-parsing helpers and persists captures so the frontend can inspect flows, packets, payloads, rules, and statistics in one place.

**Docs:** [https://sniffhound.jorgelsc.dev](https://sniffhound.jorgelsc.dev)  
**Repository:** [https://github.com/jorgelsc-dev/sniffhound](https://github.com/jorgelsc-dev/sniffhound)

---

## ✨ Highlights

- 🔍 **Passive packet capture** for IPv4, IPv6, ARP, TCP, UDP, and ICMP traffic
- 💾 **SQLite persistence** for sessions, flows, packets, payloads, and tags
- 🎨 **Live dashboard** and REST/WebSocket API powered by `wsbuilder`
- 🔐 **JWT authentication** for secure API access
- 📝 **NDJSON logging** for structured, queryable logs
- 🧪 **Comprehensive test suite** with 40+ unit/integration tests
- 🛡️ **Thread-safe** capture with RLock synchronization
- ⚡ **Native-only parsing** (no `scapy`, `dpkt`, or `impacket` dependencies)

---

## 📦 Install

### From PyPI

```bash
python -m pip install --upgrade pip
python -m pip install sniffhound
```

### From GitHub

```bash
python -m pip install "sniffhound @ git+https://github.com/jorgelsc-dev/sniffhound.git"
```

### From Source

```bash
git clone https://github.com/jorgelsc-dev/sniffhound.git
cd sniffhound
python3 -m venv .venv
. .venv/bin/activate
pip install -U pip setuptools wheel
python -m pip install .
```

> On Kali and other PEP 668-managed systems, installs must be done inside a virtual environment. Using the system interpreter directly will fail with `externally-managed-environment`.
>
> If `frontend/dist` is missing during a source install, the build backend will try to build it automatically with `npm ci && npm run build`. For frontend development you still want Node 22 LTS, because the current toolchain is validated there.

---

## 🚀 Quick Start

### Run the sniffer

```bash
# Default: HTTP on 127.0.0.1:45678
sniffhound

# Or with environment variables
SNIFFHOUND_HOST=0.0.0.0 SNIFFHOUND_PORT=8080 sniffhound
```

**Requirements:**
- Linux/Unix with `AF_PACKET` socket support
- Root/administrator permissions or `CAP_NET_RAW`
- Python 3.12+

### Access the dashboard

Open your browser to `http://localhost:45678`

On Linux, the `sniffhound` command will relaunch itself with `sudo` when capture privileges are required. You can also run it explicitly as `sudo sniffhound`.

---

## 🔐 Authentication

SniffHound now includes **JWT-based authentication** for API security.

### Generate an API Token

```python
from sniffhound.auth import generate_token

token = generate_token(user="admin", scope="full")
print(token)
```

Or use environment variable:

```bash
export SNIFFHOUND_SECRET_KEY="your-secret-key-here"
```

### Use tokens with API requests

```bash
# Authenticate with Bearer token
curl -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  http://localhost:45678/api/dashboard/

# WebSocket authentication
# Send token in Authorization header
```

### Enable required authentication

```bash
# Enforce auth on all requests
export SNIFFHOUND_REQUIRE_AUTH=1
sniffhound
```

### Token configuration

```bash
# Token expiry time (hours)
export SNIFFHOUND_TOKEN_EXPIRY_HOURS=48
```

---

## 📝 Logging

All application events are logged in **NDJSON format** (newline-delimited JSON) for easy parsing and indexing.

### Log configuration

```bash
# Enable file logging
export SNIFFHOUND_LOG_FILE=/var/log/sniffhound/events.ndjson
sniffhound
```

### Log output example

```json
{"timestamp": "2026-06-06T12:34:56.789Z", "level": "INFO", "logger": "sniffhound.capture", "message": "Starting capture on eth0", "module": "sniffer", "function": "_capture_worker", "line": 156}
{"timestamp": "2026-06-06T12:34:57.123Z", "level": "ERROR", "logger": "sniffhound.capture", "message": "permission denied: Operation not permitted", "module": "sniffer", "function": "_capture_worker", "line": 163}
```

### Log levels

```python
from sniffhound.logger import get_logger, LoggerContext

logger = get_logger("my_module", log_file="/var/log/sniffhound.log")

# Standard logging
logger.debug("Debug message")
logger.info("Info message")
logger.warning("Warning message")
logger.error("Error message", extra={"error_code": 500})

# Context manager for temporary level changes
with LoggerContext(logger, level=10):  # DEBUG
    logger.debug("This will be logged")
```

### Available loggers

```python
from sniffhound.logger import (
    get_logger,
    get_request_logger,
    get_capture_logger,
    get_honeypot_logger,
)

# HTTP request logging
req_logger = get_request_logger()

# Packet capture events
cap_logger = get_capture_logger()

# Honeypot events
hp_logger = get_honeypot_logger()
```

---

## 🧪 Testing

SniffHound includes a comprehensive test suite with **40+ tests** covering:
- Unit tests (utils, auth, logging)
- Integration tests (database, API)
- Concurrency tests (thread-safety)
- Security tests (JWT, authentication)

### Run tests

```bash
# Install dev dependencies
pip install pytest pytest-cov

# Run all tests
pytest tests/

# Run with coverage
pytest tests/ --cov=sniffhound --cov-report=html

# Run specific test
pytest tests/test_comprehensive.py::TestJWTAuth -v

# Run with verbose output
pytest tests/ -vv
```

### Test structure

```
tests/
├── test_smoke.py              # Sanity checks (original)
└── test_comprehensive.py      # Full test suite
    ├── TestVersion            # Version validation
    ├── TestNDJsonLogger       # NDJSON logging tests
    ├── TestJWTAuth            # JWT authentication tests
    ├── TestUtils              # Utility function tests
    ├── TestSniffStore         # SQLite persistence tests
    ├── TestConcurrency        # Thread-safety tests
    ├── TestSettings           # Configuration tests
    └── TestSecurityBasics     # Security verification tests
```

### Running individual test suites

```bash
# Only auth tests
pytest tests/test_comprehensive.py::TestJWTAuth -v

# Only logging tests
pytest tests/test_comprehensive.py::TestNDJsonLogger -v

# Only concurrent tests
pytest tests/test_comprehensive.py::TestConcurrency -v

# With coverage for specific module
pytest tests/ --cov=sniffhound.auth --cov-report=term-missing
```

---

## 📚 Environment Variables

### Server Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SNIFFHOUND_HOST` | `127.0.0.1` | Server bind address |
| `SNIFFHOUND_PORT` | `45678` | Server port |
| `SNIFFHOUND_DB_PATH` | `SniffHound.db` | SQLite database path |
| `SNIFFHOUND_DEBUG` | `1` | Debug mode (0/1) |
| `SNIFFHOUND_RUNTIME_MODE` | `sniffer` | Runtime mode: `sniffer` or `honeypot` |

### Capture Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SNIFFHOUND_CAPTURE_AUTO_START` | `1` | Auto-start capture on launch |
| `SNIFFHOUND_REQUIRE_ADMIN` | `auto` | Relaunch with `sudo` before capture when the process is not already elevated |
| `SNIFFHOUND_CAPTURE_INTERFACES` | `` | Comma-separated interfaces (auto-detect if empty) |
| `SNIFFHOUND_PROMISCUOUS` | `1` | Enable promiscuous mode |
| `SNIFFHOUND_SNAPLEN` | `65535` | Max packet length to capture |
| `SNIFFHOUND_POLL_TIMEOUT` | `0.5` | Socket poll timeout (seconds) |
| `SNIFFHOUND_CAPTURE_BUFFER_BYTES` | `524288` | Capture buffer size (512KB) |

### Security & Authentication

| Variable | Default | Description |
|----------|---------|-------------|
| `SNIFFHOUND_SECRET_KEY` | `hostname hash` | JWT signing key |
| `SNIFFHOUND_TOKEN_EXPIRY_HOURS` | `24` | JWT token expiry time |
| `SNIFFHOUND_REQUIRE_AUTH` | `0` | Enforce authentication (0/1) |

### Logging Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `SNIFFHOUND_LOG_FILE` | `` | NDJSON log file path |
| `SNIFFHOUND_LOG_LEVEL` | `INFO` | Log level (DEBUG/INFO/WARNING/ERROR) |

---

## 🔒 Security Best Practices

### 1. Change the secret key

```bash
export SNIFFHOUND_SECRET_KEY="your-very-secret-key-here-min-32-chars"
```

### 2. Enable authentication

```bash
export SNIFFHOUND_REQUIRE_AUTH=1
export SNIFFHOUND_TOKEN_EXPIRY_HOURS=12
```

### 3. Use logs for auditing

```bash
export SNIFFHOUND_LOG_FILE=/var/log/sniffhound/audit.ndjson
```

### 4. Bind to localhost or VPN

```bash
# NOT for production with live interfaces
export SNIFFHOUND_HOST=127.0.0.1
```

### 5. Monitor captured traffic

- Payloads may contain sensitive data (credentials, tokens)
- Configure firewall rules to restrict access
- Use HTTPS reverse proxy for remote access

---

## 📊 API Reference

### REST Endpoints

| Method | Endpoint | Description | Auth |
|--------|----------|-------------|------|
| GET | `/api/dashboard/` | Current dashboard snapshot | Optional |
| GET | `/api/endpoints/` | Endpoint catalog | Optional |
| POST | `/api/capture/start` | Start capture | Optional |
| POST | `/api/capture/stop` | Stop capture | Optional |
| GET | `/api/packets/` | List packets | Optional |
| GET | `/api/packets/:id` | Get packet details | Optional |
| GET | `/protocols/` | Supported protocols | No |
| GET | `/docs` | Runtime API documentation | No |

### WebSocket

**Endpoint:** `/ws/live`

**Message Types:**
- `packet` - New packet captured
- `stats_update` - Statistics update
- `capture_state` - Capture state change

**Authentication:**
```javascript
// Send token in Authorization header
ws = new WebSocket('ws://localhost:45678/ws/live', {
  headers: { 'Authorization': 'Bearer YOUR_TOKEN' }
});
```

---

## 🔄 Recent Changes (v0.1.0+)

### ✅ Added
- ✅ JWT authentication module (`sniffhound.auth`)
- ✅ NDJSON logging system (`sniffhound.logger`)
- ✅ Comprehensive test suite (40+ tests)
- ✅ Full API documentation

### ⚠️ Removed
- ⚠️ Demo mode (no longer available)
- ⚠️ `SNIFFHOUND_DEMO_MODE` environment variable

### 🔧 Improved
- 🔧 Thread-safe database operations
- 🔧 Structured error handling
- 🔧 Type hints throughout codebase

---

## 🛠️ Development

### Project structure

```
sniffhound/
├── app.py              # Main server & routing
├── auth.py             # JWT authentication
├── logger.py           # NDJSON logging
├── sniffer.py          # Packet capture engine
├── honeypot.py         # Honeypot mode
├── store.py            # SQLite persistence
├── settings.py         # Configuration
├── rulesets.py         # Packet classification
├── utils.py            # Utilities
└── _frontend_dist/     # Compiled Vue frontend

tests/
├── test_smoke.py       # Original sanity checks
└── test_comprehensive.py  # New comprehensive suite

frontend/
├── src/
│   ├── App.vue
│   ├── main.js
│   ├── components/
│   ├── views/
│   └── router/
└── package.json
```

### Code standards

- Python 3.12+ with PEP 604 type hints
- Thread-safe operations with RLock
- SQL injection prevention (always use `?` placeholders)
- NDJSON for all structured logging

---

## 📄 License

MIT License - See [LICENSE](LICENSE) for details

---

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines

---

## 📧 Support

Issues and questions: [GitHub Issues](https://github.com/jorgelsc-dev/sniffhound/issues)
