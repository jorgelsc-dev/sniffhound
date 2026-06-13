from __future__ import annotations

from pathlib import Path
import json

from .runtime_paths import resolve_data_file
from .utils import normalize_protocol_name, unique_ordered, safe_int


DEFAULT_RULESETS = [
    {
        "id": "builtin-arp",
        "name": "ARP discovery",
        "description": "Layer 2 ARP packets and address resolution chatter.",
        "enabled": True,
        "priority": 10,
        "source": "builtin",
        "match": {"eth_types": [0x0806]},
        "action": {"tag": "arp", "label": "ARP", "severity": "info"},
    },
    {
        "id": "builtin-ipv6",
        "name": "IPv6 traffic",
        "description": "Any IPv6 frame, including neighbor discovery and extension headers.",
        "enabled": True,
        "priority": 20,
        "source": "builtin",
        "match": {"ip_versions": [6]},
        "action": {"tag": "ipv6", "label": "IPv6", "severity": "info"},
    },
    {
        "id": "builtin-dns",
        "name": "DNS telemetry",
        "description": "DNS queries and responses over UDP/TCP port 53.",
        "enabled": True,
        "priority": 30,
        "source": "builtin",
        "match": {"protocols": ["udp", "tcp"], "ports": [53]},
        "action": {"tag": "dns", "label": "DNS", "severity": "low"},
    },
    {
        "id": "builtin-http",
        "name": "HTTP traffic",
        "description": "HTTP requests, responses and common web ports.",
        "enabled": True,
        "priority": 40,
        "source": "builtin",
        "match": {
            "protocols": ["tcp"],
            "ports": [80, 8080, 8000, 8888, 5000, 3000],
            "payload_contains": ["GET ", "POST ", "HEAD ", "HTTP/1.", "PUT ", "DELETE "],
        },
        "action": {"tag": "http", "label": "HTTP", "severity": "medium"},
    },
    {
        "id": "builtin-tls",
        "name": "TLS handshake",
        "description": "TLS client/server handshakes and common secure web ports.",
        "enabled": True,
        "priority": 50,
        "source": "builtin",
        "match": {"protocols": ["tcp"], "ports": [443, 8443, 9443], "payload_prefix_hex": ["16"]},
        "action": {"tag": "tls", "label": "TLS", "severity": "medium"},
    },
    {
        "id": "builtin-icmp",
        "name": "ICMP telemetry",
        "description": "Echo, destination unreachable and other ICMP messages.",
        "enabled": True,
        "priority": 60,
        "source": "builtin",
        "match": {"protocols": ["icmp", "icmpv6"]},
        "action": {"tag": "icmp", "label": "ICMP", "severity": "info"},
    },
]


def _default_ruleset_path() -> Path:
    return resolve_data_file("default_rulesets.json")


def load_builtin_rulesets() -> list[dict]:
    path = _default_ruleset_path()
    if path.exists():
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(payload, list):
                return [normalize_ruleset(item, allow_source=True) for item in payload if isinstance(item, dict)]
        except Exception:
            pass
    return [normalize_ruleset(item, allow_source=True) for item in DEFAULT_RULESETS]


def normalize_ruleset(item: dict, allow_source: bool = False) -> dict:
    data = item if isinstance(item, dict) else {}
    rule_id = str(data.get("id") or data.get("slug") or data.get("name") or "").strip()
    if not rule_id:
        rule_id = "custom-rule"
    name = str(data.get("name") or rule_id).strip() or rule_id
    description = str(data.get("description") or "").strip()
    enabled = bool(data.get("enabled", True))
    priority = safe_int(data.get("priority", 100), 100)
    match = data.get("match") if isinstance(data.get("match"), dict) else {}
    action = data.get("action") if isinstance(data.get("action"), dict) else {}
    normalized = {
        "id": rule_id,
        "name": name,
        "description": description,
        "enabled": enabled,
        "priority": priority,
        "match": normalize_match(match),
        "action": normalize_action(action),
    }
    if allow_source:
        normalized["source"] = str(data.get("source") or "custom").strip() or "custom"
    return normalized


def normalize_match(match: dict) -> dict:
    data = match if isinstance(match, dict) else {}

    def _list(key):
        raw = data.get(key, [])
        if isinstance(raw, (list, tuple, set)):
            return unique_ordered([normalize_protocol_name(item) if key == "protocols" else item for item in raw if item not in (None, "")])
        if raw in (None, ""):
            return []
        return [normalize_protocol_name(raw) if key == "protocols" else raw]

    def _int_list(key):
        values = []
        raw = data.get(key, [])
        if not isinstance(raw, (list, tuple, set)):
            raw = [raw]
        for item in raw:
            try:
                values.append(int(item))
            except Exception:
                continue
        return unique_ordered(values)

    normalized = {
        "protocols": _list("protocols"),
        "ip_versions": _int_list("ip_versions"),
        "eth_types": _int_list("eth_types"),
        "ports": _int_list("ports"),
        "src_ports": _int_list("src_ports"),
        "dst_ports": _int_list("dst_ports"),
        "payload_contains": [str(item) for item in _list("payload_contains")],
        "payload_prefix_hex": [str(item).lower().replace("0x", "") for item in _list("payload_prefix_hex")],
        "payload_regex": [str(item) for item in _list("payload_regex")],
        "min_length": safe_int(data.get("min_length", 0), 0),
        "max_length": safe_int(data.get("max_length", 0), 0),
    }
    return normalized


def normalize_action(action: dict) -> dict:
    data = action if isinstance(action, dict) else {}
    return {
        "tag": str(data.get("tag") or "").strip(),
        "label": str(data.get("label") or "").strip(),
        "severity": str(data.get("severity") or "info").strip().lower() or "info",
    }


def rule_matches_packet(rule: dict, packet: dict) -> bool:
    if not rule or not rule.get("enabled", True):
        return False
    match = rule.get("match") if isinstance(rule.get("match"), dict) else {}
    proto = normalize_protocol_name(packet.get("proto"))
    packet_text = " ".join(
        str(value)
        for value in (
            packet.get("summary"),
            packet.get("payload_text"),
            packet.get("src_ip"),
            packet.get("dst_ip"),
            packet.get("eth_src"),
            packet.get("eth_dst"),
        )
        if value not in (None, "")
    ).lower()
    payload_hex = str(packet.get("payload_hex") or "").lower()
    payload_length = safe_int(packet.get("payload_len", 0), 0)
    packet_length = safe_int(packet.get("length", 0), 0)

    protocols = [normalize_protocol_name(item) for item in match.get("protocols", []) if str(item).strip()]
    if protocols and proto not in protocols:
        return False

    ip_versions = [safe_int(item, 0) for item in match.get("ip_versions", []) if safe_int(item, 0)]
    if ip_versions and safe_int(packet.get("ip_version", 0), 0) not in ip_versions:
        return False

    eth_types = [safe_int(item, 0) for item in match.get("eth_types", []) if safe_int(item, 0)]
    if eth_types and safe_int(packet.get("eth_type", 0), 0) not in eth_types:
        return False

    ports = [safe_int(item, 0) for item in match.get("ports", []) if safe_int(item, 0)]
    if ports:
        src_port = safe_int(packet.get("src_port", 0), 0)
        dst_port = safe_int(packet.get("dst_port", 0), 0)
        if src_port not in ports and dst_port not in ports:
            return False

    src_ports = [safe_int(item, 0) for item in match.get("src_ports", []) if safe_int(item, 0)]
    if src_ports and safe_int(packet.get("src_port", 0), 0) not in src_ports:
        return False

    dst_ports = [safe_int(item, 0) for item in match.get("dst_ports", []) if safe_int(item, 0)]
    if dst_ports and safe_int(packet.get("dst_port", 0), 0) not in dst_ports:
        return False

    needles = [str(item).lower() for item in match.get("payload_contains", []) if str(item).strip()]
    if needles and not any(needle in packet_text for needle in needles):
        return False

    prefix_hex = [str(item).lower().replace("0x", "") for item in match.get("payload_prefix_hex", []) if str(item).strip()]
    if prefix_hex and not any(payload_hex.startswith(prefix) for prefix in prefix_hex):
        return False

    regexes = [str(item).strip() for item in match.get("payload_regex", []) if str(item).strip()]
    if regexes:
        import re

        if not any(re.search(pattern, packet_text, re.IGNORECASE) for pattern in regexes):
            return False

    min_length = safe_int(match.get("min_length", 0), 0)
    if min_length and packet_length < min_length:
        return False

    max_length = safe_int(match.get("max_length", 0), 0)
    if max_length and packet_length > max_length:
        return False

    return True


def classify_packet(packet: dict, rulesets: list[dict]) -> list[dict]:
    matches = []
    for rule in sorted(rulesets, key=lambda item: (safe_int(item.get("priority", 100), 100), str(item.get("name") or ""))):
        if rule_matches_packet(rule, packet):
            action = rule.get("action") if isinstance(rule.get("action"), dict) else {}
            matches.append(
                {
                    "rule_id": rule.get("id"),
                    "rule_name": rule.get("name"),
                    "tag": action.get("tag") or rule.get("id"),
                    "label": action.get("label") or rule.get("name"),
                    "severity": action.get("severity") or "info",
                }
            )
    return matches

