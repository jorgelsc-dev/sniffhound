from __future__ import annotations

from os import getenv


def _env(key: str, default: str = "") -> str:
    return getenv(key, default)


def _as_int(value, default: int) -> int:
    try:
        return int(value)
    except Exception:
        return int(default)


def _as_float(value, default: float) -> float:
    try:
        return float(value)
    except Exception:
        return float(default)


def _as_bool(value, default: bool = False) -> bool:
    raw = str(value if value is not None else "").strip().lower()
    if not raw:
        return bool(default)
    return raw in {"1", "true", "yes", "on", "y"}


HOST = str(_env("SNIFFHOUND_HOST", _env("HOST", "127.0.0.1"))).strip() or "127.0.0.1"
PORT = _as_int(_env("SNIFFHOUND_PORT", _env("PORT", "45678")), 45678)
DB_PATH = str(_env("SNIFFHOUND_DB_PATH", "SniffHound.db")).strip() or "SniffHound.db"
DEBUG = _as_bool(_env("SNIFFHOUND_DEBUG", "1"), default=True)
RUNTIME_MODE = str(_env("SNIFFHOUND_RUNTIME_MODE", _env("SNIFFHOUND_MODE", "sniffer"))).strip().lower() or "sniffer"

CAPTURE_AUTO_START = _as_bool(_env("SNIFFHOUND_CAPTURE_AUTO_START", "1"), default=True)
CAPTURE_DEMO_MODE = _as_bool(_env("SNIFFHOUND_CAPTURE_DEMO_MODE", "0"), default=False)
CAPTURE_INTERFACES = tuple(
    item.strip()
    for item in str(_env("SNIFFHOUND_CAPTURE_INTERFACES", "")).split(",")
    if item.strip()
)
CAPTURE_PROMISCUOUS = _as_bool(_env("SNIFFHOUND_PROMISCUOUS", "1"), default=True)
CAPTURE_SNAPLEN = max(64, _as_int(_env("SNIFFHOUND_SNAPLEN", "65535"), 65535))
CAPTURE_POLL_TIMEOUT = max(0.05, _as_float(_env("SNIFFHOUND_POLL_TIMEOUT", "0.5"), 0.5))
CAPTURE_BUFFER_BYTES = max(65536, _as_int(_env("SNIFFHOUND_CAPTURE_BUFFER_BYTES", "524288"), 524288))

DEFAULT_RULESET_FILE = str(_env("SNIFFHOUND_RULESET_FILE", "default_rulesets.json")).strip()
DEFAULT_DOCS_TITLE = str(_env("SNIFFHOUND_DOCS_TITLE", "SniffHound")).strip() or "SniffHound"
DEFAULT_DOCS_DESCRIPTION = str(
    _env(
        "SNIFFHOUND_DOCS_DESCRIPTION",
        "Native packet sniffer with SQLite persistence, live stats, an optional honeypot mode, and a wsbuilder frontend.",
    )
).strip()
