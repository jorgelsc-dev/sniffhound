# Quick Reference

Fast lookup for SniffHound commands and configurations.

## Installation

```bash
pip install sniffhound
```

## Basic Usage

```bash
sniffhound                                    # Start with defaults
SNIFFHOUND_PORT=8080 sniffhound              # Custom port
SNIFFHOUND_HOST=0.0.0.0 sniffhound           # Listen on all interfaces
```

## Environment Variables

### Server
```bash
SNIFFHOUND_HOST=127.0.0.1                    # Bind address
SNIFFHOUND_PORT=45678                        # Port
SNIFFHOUND_DB_PATH=SniffHound.db            # Database file
```

### Security
```bash
SNIFFHOUND_SECRET_KEY=your-secret-key       # JWT secret
SNIFFHOUND_REQUIRE_AUTH=1                   # Enforce authentication
SNIFFHOUND_TOKEN_EXPIRY_HOURS=24            # Token lifetime
```

### Logging
```bash
SNIFFHOUND_LOG_FILE=/var/log/sniffhound.ndjson  # Enable file logging
SNIFFHOUND_LOG_LEVEL=INFO                        # Log level
```

### Capture
```bash
SNIFFHOUND_CAPTURE_INTERFACES=eth0,eth1    # Specific interfaces
SNIFFHOUND_CAPTURE_AUTO_START=1             # Auto-start capture
SNIFFHOUND_PROMISCUOUS=1                    # Promiscuous mode
```

## API Quick Commands

```bash
# Generate token
TOKEN=$(python3 -c "from sniffhound.auth import generate_token; print(generate_token())")

# Get dashboard
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:45678/api/dashboard/

# Start capture
curl -X POST -H "Authorization: Bearer $TOKEN" \
  http://localhost:45678/api/capture/start

# Stop capture
curl -X POST -H "Authorization: Bearer $TOKEN" \
  http://localhost:45678/api/capture/stop

# List packets
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:45678/api/packets/
```

## Testing

```bash
pytest tests/                                # Run all tests
pytest tests/test_comprehensive.py -v       # Verbose
pytest tests/ --cov=sniffhound              # With coverage
pytest tests/ -k "auth"                     # Only auth tests
```

## Logging

```bash
# View logs
tail -f /var/log/sniffhound.ndjson | jq '.'

# Filter errors
cat /var/log/sniffhound.ndjson | jq 'select(.level=="ERROR")'

# Count by logger
cat /var/log/sniffhound.ndjson | jq -s 'group_by(.logger) | map({logger: .[0].logger, count: length})'
```

## Python Examples

### Generate Token
```python
from sniffhound.auth import generate_token
token = generate_token(user="admin")
print(token)
```

### Get Logger
```python
from sniffhound.logger import get_logger
logger = get_logger("my_module", log_file="/var/log/app.log")
logger.info("Event occurred", extra={"key": "value"})
```

### Query Database
```python
from sniffhound.store import SniffStore
store = SniffStore("SniffHound.db")
summary = store.summary_counts()
print(f"Packets: {summary['packets']}")
store.close()
```

## WebSocket Connection

```javascript
const ws = new WebSocket('ws://localhost:45678/ws/live');
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log(data);  // packet, stats_update, etc
};
```

## File Locations

- Dashboard: `http://localhost:45678`
- API Docs: `http://localhost:45678/docs`
- Endpoint Catalog: `http://localhost:45678/api/endpoints/`
- Database: `./SniffHound.db`
- Logs: `$SNIFFHOUND_LOG_FILE` (if configured)

## Troubleshooting

```bash
# Permission errors?
sudo setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/sniffhound

# Can't access dashboard?
curl http://localhost:45678/  # Check if running

# Database locked?
rm SniffHound.db-wal          # Clear WAL file

# Token issues?
python3 -c "from sniffhound.auth import generate_token; print(generate_token())"
```

## Documentation

- Full docs: [README.md](README.md)
- Architecture: [ARCHITECTURE.md](ARCHITECTURE.md)
- Examples: [EXAMPLES.md](EXAMPLES.md)
- GitHub: https://github.com/jorgelsc-dev/sniffhound
