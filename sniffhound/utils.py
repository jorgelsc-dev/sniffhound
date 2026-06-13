from __future__ import annotations

import ipaddress
import json
import math
import re
from datetime import datetime, timezone


PRINTABLE_RE = re.compile(r"[^\x20-\x7E]+")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def clamp_int(value, minimum, maximum, default=None):
    try:
        number = int(value)
    except Exception:
        return default
    return max(int(minimum), min(int(maximum), number))


def safe_int(value, default=0):
    try:
        return int(value)
    except Exception:
        return int(default)


def safe_float(value, default=0.0):
    try:
        return float(value)
    except Exception:
        return float(default)


def json_dumps(value) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def json_loads(value, default=None):
    if value in (None, ""):
        return default
    try:
        return json.loads(value)
    except Exception:
        return default


def normalize_text(value, limit=240):
    raw = "" if value is None else str(value)
    cleaned = PRINTABLE_RE.sub(" ", raw).strip()
    cleaned = re.sub(r"\s+", " ", cleaned)
    if limit and len(cleaned) > limit:
        return cleaned[: max(0, int(limit) - 1)].rstrip() + "…"
    return cleaned


def bytes_to_hex_preview(payload: bytes, limit: int = 256, max_length: int | None = None) -> str:
    if not payload:
        return ""
    effective_limit = max_length if max_length is not None else limit
    return payload[: max(0, int(effective_limit))].hex()


def bytes_to_text_preview(payload: bytes, limit: int = 240) -> str:
    if not payload:
        return ""
    text = payload.decode("utf-8", errors="ignore")
    return normalize_text(text, limit=limit)


def format_mac(raw: bytes | bytearray | None) -> str:
    if not raw:
        return ""
    return ":".join(f"{byte:02x}" for byte in bytes(raw)[:6])


def is_printable_payload(payload: bytes) -> bool:
    if not payload:
        return False
    printable = 0
    for byte in payload[: min(len(payload), 128)]:
        if 32 <= byte <= 126 or byte in {9, 10, 13}:
            printable += 1
    return printable >= max(8, math.ceil(min(len(payload), 128) * 0.55))


def unique_ordered(values):
    seen = set()
    ordered = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return ordered


def normalize_protocol_name(value: str) -> str:
    return str(value or "").strip().lower() or "unknown"


def stable_flow_key(proto: str, src_ip: str, src_port, dst_ip: str, dst_port) -> str:
    left = f"{src_ip}:{src_port}"
    right = f"{dst_ip}:{dst_port}"
    if left <= right:
        ordered = (left, right)
    else:
        ordered = (right, left)
    return f"{normalize_protocol_name(proto)}|{ordered[0]}|{ordered[1]}"


def local_ip_candidates() -> set[str]:
    candidates = {"127.0.0.1", "::1"}
    try:
        import socket

        hostname = socket.gethostname()
        for family, _, _, _, sockaddr in socket.getaddrinfo(hostname, None):
            if not sockaddr:
                continue
            address = sockaddr[0]
            if isinstance(address, str):
                candidates.add(address)
    except Exception:
        pass
    return candidates


def is_probably_ipv4(text: str) -> bool:
    try:
        ipaddress.IPv4Address(str(text).strip())
        return True
    except Exception:
        return False


def is_probably_ipv6(text: str) -> bool:
    try:
        ipaddress.IPv6Address(str(text).strip())
        return True
    except Exception:
        return False
