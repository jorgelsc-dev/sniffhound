# SniffHound Usage Examples

Practical examples for common SniffHound operations.

---

## Authentication & API Access

### Generate and use JWT tokens

```bash
# Option 1: Generate token via Python
python3 << 'EOF'
from sniffhound.auth import generate_token

token = generate_token(user="admin", scope="full:read")
print(f"Token: {token}")
EOF

# Option 2: Curl with Bearer token
TOKEN="your.jwt.token.here"
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:45678/api/dashboard/
```

### Python API client example

```python
import requests
from sniffhound.auth import generate_token

# Generate token
token = generate_token(user="analyst", scope="read:packets")

# Make authenticated request
headers = {"Authorization": f"Bearer {token}"}

# Get dashboard snapshot
response = requests.get(
    "http://localhost:45678/api/dashboard/",
    headers=headers
)

if response.status_code == 200:
    data = response.json()
    print(f"Packets: {data['summary']['packets']}")
    print(f"Unique hosts: {data['summary']['unique_hosts']}")
else:
    print(f"Error: {response.status_code}")
```

### JavaScript/Fetch example

```javascript
// Generate token (backend call first)
async function getToken() {
  const response = await fetch('/api/token', {
    method: 'POST',
    body: JSON.stringify({ user: 'user@example.com', password: 'secret' })
  });
  return response.json().token;
}

// Use token in requests
const token = await getToken();

const response = await fetch('http://localhost:45678/api/packets/', {
  headers: {
    'Authorization': `Bearer ${token}`
  }
});

const packets = await response.json();
console.log(`Found ${packets.length} packets`);
```

---

## Capture Operations

### Start capturing on specific interfaces

```bash
# Specify interfaces
export SNIFFHOUND_CAPTURE_INTERFACES="eth0,eth1,docker0"
sniffhound
```

### Control capture via API

```bash
TOKEN="your_token_here"

# Start capture
curl -X POST \
  -H "Authorization: Bearer $TOKEN" \
  http://localhost:45678/api/capture/start

# Stop capture
curl -X POST \
  -H "Authorization: Bearer $TOKEN" \
  http://localhost:45678/api/capture/stop

# Get capture status
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:45678/api/dashboard/ | jq '.sniffer'
```

### Python capture control

```python
import requests
import json

token = "your.jwt.token"
headers = {"Authorization": f"Bearer {token}"}
base_url = "http://localhost:45678"

# Start
start = requests.post(f"{base_url}/api/capture/start", headers=headers)
print(json.dumps(start.json(), indent=2))

# Monitor
import time
for i in range(5):
    snapshot = requests.get(f"{base_url}/api/dashboard/", headers=headers)
    data = snapshot.json()
    print(f"Packets: {data['summary']['packets']}")
    time.sleep(1)

# Stop
stop = requests.post(f"{base_url}/api/capture/stop", headers=headers)
print(json.dumps(stop.json(), indent=2))
```

---

## Logging & Monitoring

### Enable structured logging

```bash
# Enable file logging
export SNIFFHOUND_LOG_FILE="/var/log/sniffhound/app.ndjson"
export SNIFFHOUND_LOG_LEVEL="INFO"
sniffhound
```

### Parse NDJSON logs

```bash
# View latest logs
tail -f /var/log/sniffhound/app.ndjson | jq '.'

# Filter by level
cat /var/log/sniffhound/app.ndjson | jq 'select(.level=="ERROR")'

# Extract specific fields
cat /var/log/sniffhound/app.ndjson | jq '.message,.timestamp'

# Count by logger
cat /var/log/sniffhound/app.ndjson | jq -s 'group_by(.logger) | map({logger: .[0].logger, count: length})'

# Find errors in capture
cat /var/log/sniffhound/app.ndjson | jq 'select(.logger | contains("capture")) | select(.level=="ERROR")'
```

### Python log processing

```python
import json
import sys
from collections import defaultdict

# Parse NDJSON log file
log_file = "/var/log/sniffhound/app.ndjson"
errors_by_module = defaultdict(list)

with open(log_file) as f:
    for line in f:
        entry = json.loads(line)
        if entry['level'] == 'ERROR':
            module = entry.get('module', 'unknown')
            errors_by_module[module].append(entry)

# Print summary
for module, errors in errors_by_module.items():
    print(f"{module}: {len(errors)} errors")
    for error in errors[:3]:  # First 3
        print(f"  - {error['message']}")
```

### Real-time monitoring with tail

```bash
# Color-coded error monitoring
tail -f /var/log/sniffhound/app.ndjson | \
  jq --raw-output 'if .level=="ERROR" then "\u001b[31m\(.message)\u001b[0m" else "\(.message)" end'

# Extract metrics
tail -f /var/log/sniffhound/app.ndjson | \
  jq 'select(.level=="INFO") | {timestamp, logger, message}'
```

---

## WebSocket Integration

### Connect and listen for events

```javascript
const token = "your.jwt.token";

// Connect
const ws = new WebSocket('ws://localhost:45678/ws/live');

// Send authentication (if required)
ws.onopen = () => {
  ws.send(JSON.stringify({
    type: 'auth',
    token: token
  }));
};

// Handle messages
ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log(`Event type: ${data.type}`);
  
  if (data.type === 'packet') {
    const packet = data.packet;
    console.log(`${packet.src_ip}:${packet.src_port} → ${packet.dst_ip}:${packet.dst_port}`);
  }
  
  if (data.type === 'stats_update') {
    console.log(`Total packets: ${data.stats.packets_seen}`);
  }
};

// Handle errors
ws.onerror = (error) => console.error("WebSocket error:", error);
ws.onclose = () => console.log("Connection closed");
```

### Python WebSocket client

```python
import asyncio
import json
from websockets import connect

async def listen_packets():
    uri = "ws://localhost:45678/ws/live"
    token = "your.jwt.token"
    
    async with connect(uri) as websocket:
        # Send auth if required
        await websocket.send(json.dumps({
            "type": "auth",
            "token": token
        }))
        
        # Listen for events
        while True:
            message = await websocket.recv()
            data = json.loads(message)
            
            if data['type'] == 'packet':
                packet = data['packet']
                print(f"{packet['src_ip']}:{packet['src_port']} "
                      f"→ {packet['dst_ip']}:{packet['dst_port']} "
                      f"({packet['proto']})")
            
            elif data['type'] == 'stats_update':
                print(f"Stats: {data['stats']}")

asyncio.run(listen_packets())
```

---

## Testing

### Run test suite

```bash
# All tests
pytest tests/ -v

# Specific test class
pytest tests/test_comprehensive.py::TestJWTAuth -v

# With coverage
pytest tests/ --cov=sniffhound --cov-report=html

# Only auth tests
pytest tests/ -k "auth" -v

# Verbose with output
pytest tests/ -vv -s
```

### Manual API testing

```bash
# Generate test token
TOKEN=$(python3 -c "from sniffhound.auth import generate_token; print(generate_token())")
echo "Token: $TOKEN"

# Test unauthenticated endpoint
curl http://localhost:45678/protocols/ | jq '.[]'

# Test authenticated endpoint
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:45678/api/dashboard/ | jq '.summary'

# Test invalid token
curl -H "Authorization: Bearer invalid.token.here" \
  http://localhost:45678/api/dashboard/ 2>&1 | head -5

# Test expired token
python3 << 'EOF'
import time
from sniffhound.auth import encode_jwt

exp = int(time.time()) - 3600  # Expired 1 hour ago
expired_token = encode_jwt({"user": "test", "exp": exp, "iat": exp - 7200})
print(f"Expired token: {expired_token}")
EOF

# Use it
curl -H "Authorization: Bearer $EXPIRED_TOKEN" \
  http://localhost:45678/api/dashboard/
```

---

## Database Operations

### Query captured packets

```python
from pathlib import Path
from sniffhound.store import SniffStore

# Open database
db_path = Path("SniffHound.db")
store = SniffStore(db_path)

try:
    # Get summary
    summary = store.summary_counts()
    print(f"Total packets: {summary['packets']}")
    print(f"Total hosts: {summary['unique_hosts']}")
    
    # List packets (raw)
    packets = store.list_packets(limit=10)
    for pkt in packets:
        print(f"{pkt['src_ip']} → {pkt['dst_ip']} ({pkt['proto']})")
    
    # Dashboard snapshot
    dashboard = store.dashboard_snapshot()
    print(f"Top flows: {dashboard['top_flows']}")
    
finally:
    store.close()
```

### Export packet data

```python
import json
import csv
from sniffhound.store import SniffStore

store = SniffStore("SniffHound.db")

try:
    packets = store.list_packets(limit=1000)
    
    # Export to JSON
    with open("packets.json", "w") as f:
        json.dump(packets, f, indent=2)
    
    # Export to CSV
    if packets:
        with open("packets.csv", "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=packets[0].keys())
            writer.writeheader()
            writer.writerows(packets)
    
    print(f"Exported {len(packets)} packets")

finally:
    store.close()
```

---

## Performance Testing

### Benchmark packet capture

```bash
# Run with high buffer
SNIFFHOUND_CAPTURE_BUFFER_BYTES=1048576 sniffhound &

# Generate traffic (in another terminal)
timeout 10s tcpdump -i eth0 -c 1000 > /dev/null

# Check stats
curl http://localhost:45678/api/dashboard/ | jq '.sniffer.packets_seen'

# Calculate throughput
# packets_seen / 10 = packets per second
```

### Stress test API

```bash
# Using Apache Bench
TOKEN=$(python3 -c "from sniffhound.auth import generate_token; print(generate_token())")

ab -n 1000 -c 10 \
  -H "Authorization: Bearer $TOKEN" \
  http://localhost:45678/api/dashboard/

# Using wrk
wrk -t4 -c100 -d30s \
  -H "Authorization: Bearer $TOKEN" \
  http://localhost:45678/api/dashboard/
```

---

## Security Hardening

### Production deployment

```bash
#!/bin/bash
# production.sh

export SNIFFHOUND_HOST="127.0.0.1"          # Localhost only
export SNIFFHOUND_PORT="45678"
export SNIFFHOUND_DB_PATH="/data/sniffhound.db"
export SNIFFHOUND_SECRET_KEY="$(openssl rand -hex 32)"
export SNIFFHOUND_REQUIRE_AUTH=1
export SNIFFHOUND_TOKEN_EXPIRY_HOURS=12
export SNIFFHOUND_LOG_FILE="/var/log/sniffhound/app.ndjson"
export SNIFFHOUND_CAPTURE_INTERFACES="eth0,eth1"

# Run with reduced privileges
exec sudo -u sniffhound sniffhound
```

### Reverse proxy (Nginx)

```nginx
server {
    listen 443 ssl http2;
    server_name sniffhound.example.com;
    
    ssl_certificate /etc/ssl/certs/cert.pem;
    ssl_certificate_key /etc/ssl/private/key.pem;
    
    location / {
        proxy_pass http://localhost:45678;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Authorization $http_authorization;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

---

## Troubleshooting

### Common issues

```bash
# No packets captured - check permissions
sudo getcap /usr/local/bin/sniffhound
sudo setcap cap_net_raw,cap_net_admin=eip /usr/local/bin/sniffhound

# Permission errors - run as root (not recommended)
sudo sniffhound

# Database locked - SQLite concurrent access
# Check logs for write contention
tail /var/log/sniffhound/app.ndjson | grep -i "database"

# WebSocket connection refused
curl -v http://localhost:45678/
# Check if server is running and accessible
```

---

## Integration Examples

### Monitoring stack

```dockerfile
# docker-compose.yml
version: '3.8'

services:
  sniffhound:
    image: sniffhound:latest
    environment:
      SNIFFHOUND_HOST: "0.0.0.0"
      SNIFFHOUND_LOG_FILE: "/var/log/sniffhound/app.ndjson"
    volumes:
      - /var/log/sniffhound:/var/log/sniffhound
      - ./SniffHound.db:/data/SniffHound.db
    network_mode: host
    cap_add:
      - NET_RAW
      - NET_ADMIN

  prometheus:
    image: prom/prometheus
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
    ports:
      - "9090:9090"

  grafana:
    image: grafana/grafana
    ports:
      - "3000:3000"
    depends_on:
      - prometheus
```

---

## Advanced Usage

### Custom rule deployment

```python
from sniffhound.store import SniffStore

store = SniffStore("SniffHound.db")

custom_rules = {
    "name": "security_rules",
    "rules": [
        {
            "name": "ssh_login_attempts",
            "pattern": "SSH.*successful|authentication.*failed",
            "field": "payload_text"
        },
        {
            "name": "sql_injection",
            "pattern": r"(UNION.*SELECT|OR.*1=1|EXEC|DROP)",
            "field": "payload_text"
        }
    ]
}

store.register_ruleset(custom_rules)
```

### Real-time alerting

```python
import requests
import time
from sniffhound.store import SniffStore

store = SniffStore("SniffHound.db")
last_packet_id = 0

def send_alert(packet, rule):
    requests.post("https://slack.com/hooks/...", json={
        "text": f"🚨 Rule matched: {rule}",
        "details": f"{packet['src_ip']} → {packet['dst_ip']}"
    })

while True:
    packets = store.list_packets(limit=100)
    for packet in packets:
        if packet['id'] > last_packet_id:
            matches = store.classify_packet(packet)
            for match in matches:
                send_alert(packet, match['rule'])
            last_packet_id = packet['id']
    time.sleep(1)
```

---

For more examples and documentation, visit:
- GitHub: https://github.com/jorgelsc-dev/sniffhound
- Docs: https://sniffhound.jorgelsc.dev
