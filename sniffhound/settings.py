from __future__ import annotations

from os import getenv
from pathlib import Path


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


def default_data_dir() -> Path:
    xdg_data_home = str(_env("XDG_DATA_HOME", "")).strip()
    base = Path(xdg_data_home) if xdg_data_home else Path.home() / ".local" / "share"
    return base / "sniffhound"


# Fixed per-user data directory (XDG-style) rather than the process cwd, so
# uninstall tooling (see scripts/build_deb.sh's postrm) has one known
# location to purge instead of guessing at whatever cwd sniffhound was last
# run from.
DATA_DIR = Path(str(_env("SNIFFHOUND_DATA_DIR", "")).strip() or default_data_dir())
DB_PATH = str(_env("SNIFFHOUND_DB_PATH", "")).strip() or str(DATA_DIR / "SniffHound.db")
DEBUG = _as_bool(_env("SNIFFHOUND_DEBUG", "1"), default=True)
RUNTIME_MODE = str(_env("SNIFFHOUND_RUNTIME_MODE", _env("SNIFFHOUND_MODE", "sniffer"))).strip().lower() or "sniffer"

CAPTURE_AUTO_START = _as_bool(_env("SNIFFHOUND_CAPTURE_AUTO_START", "0"), default=False)
CAPTURE_INTERFACES = tuple(
    item.strip()
    for item in str(_env("SNIFFHOUND_CAPTURE_INTERFACES", "")).split(",")
    if item.strip()
)
CAPTURE_PROMISCUOUS = _as_bool(_env("SNIFFHOUND_PROMISCUOUS", "1"), default=True)
CAPTURE_SNAPLEN = max(64, _as_int(_env("SNIFFHOUND_SNAPLEN", "65535"), 65535))
CAPTURE_POLL_TIMEOUT = max(0.05, _as_float(_env("SNIFFHOUND_POLL_TIMEOUT", "0.5"), 0.5))
CAPTURE_BUFFER_BYTES = max(65536, _as_int(_env("SNIFFHOUND_CAPTURE_BUFFER_BYTES", "524288"), 524288))

WIFI_INTERFACE = str(_env("SNIFFHOUND_WIFI_INTERFACE", "")).strip()
ICMP_FLOOD_WINDOW_SECONDS = max(1, _as_int(_env("SNIFFHOUND_ICMP_FLOOD_WINDOW_SECONDS", "5"), 5))
ICMP_FLOOD_THRESHOLD = max(1, _as_int(_env("SNIFFHOUND_ICMP_FLOOD_THRESHOLD", "30"), 30))
WIFI_DEAUTH_WINDOW_SECONDS = max(1, _as_int(_env("SNIFFHOUND_WIFI_DEAUTH_WINDOW_SECONDS", "10"), 10))
WIFI_DEAUTH_THRESHOLD = max(1, _as_int(_env("SNIFFHOUND_WIFI_DEAUTH_THRESHOLD", "10"), 10))
ARP_SPOOF_COOLDOWN_SECONDS = max(1, _as_int(_env("SNIFFHOUND_ARP_SPOOF_COOLDOWN_SECONDS", "30"), 30))
ROGUE_AP_COOLDOWN_SECONDS = max(1, _as_int(_env("SNIFFHOUND_ROGUE_AP_COOLDOWN_SECONDS", "60"), 60))
PORT_SCAN_WINDOW_SECONDS = max(1, _as_int(_env("SNIFFHOUND_PORT_SCAN_WINDOW_SECONDS", "10"), 10))
PORT_SCAN_DISTINCT_PORTS_THRESHOLD = max(1, _as_int(_env("SNIFFHOUND_PORT_SCAN_DISTINCT_PORTS_THRESHOLD", "15"), 15))
SYN_FLOOD_WINDOW_SECONDS = max(1, _as_int(_env("SNIFFHOUND_SYN_FLOOD_WINDOW_SECONDS", "5"), 5))
SYN_FLOOD_THRESHOLD = max(1, _as_int(_env("SNIFFHOUND_SYN_FLOOD_THRESHOLD", "50"), 50))
BRUTE_FORCE_WINDOW_SECONDS = max(1, _as_int(_env("SNIFFHOUND_BRUTE_FORCE_WINDOW_SECONDS", "30"), 30))
BRUTE_FORCE_THRESHOLD = max(1, _as_int(_env("SNIFFHOUND_BRUTE_FORCE_THRESHOLD", "8"), 8))
DNS_QUERY_FLOOD_WINDOW_SECONDS = max(1, _as_int(_env("SNIFFHOUND_DNS_QUERY_FLOOD_WINDOW_SECONDS", "10"), 10))
DNS_QUERY_FLOOD_THRESHOLD = max(1, _as_int(_env("SNIFFHOUND_DNS_QUERY_FLOOD_THRESHOLD", "60"), 60))
DHCP_ROGUE_SERVER_COOLDOWN_SECONDS = max(1, _as_int(_env("SNIFFHOUND_DHCP_ROGUE_SERVER_COOLDOWN_SECONDS", "60"), 60))

DEFAULT_RULESET_FILE = str(_env("SNIFFHOUND_RULESET_FILE", "default_rulesets.json")).strip()
MONITOR_FILTER_DEFAULT = _as_bool(_env("SNIFFHOUND_MONITOR_FILTER_DEFAULT", "1"), default=True)
DEFAULT_DOCS_TITLE = str(_env("SNIFFHOUND_DOCS_TITLE", "SniffHound")).strip() or "SniffHound"
DEFAULT_DOCS_DESCRIPTION = str(
    _env(
        "SNIFFHOUND_DOCS_DESCRIPTION",
        "Native packet sniffer with SQLite persistence, live stats, an optional honeypot mode, and a wsbuilder frontend.",
    )
).strip()

# IPC between the unprivileged web process and the privileged capture process
# (see sniffhound/ipc.py, sniffhound/capture_service.py). Read lazily via
# functions rather than cached at import time: `manage.py` generates the
# socket path/token and injects them into os.environ for its own subsequent
# `from .app import ...`, which happens after `sniffhound.settings` has
# already been imported once - module-level constants would freeze the
# pre-injection (empty) values.


def default_ipc_socket_path(port: int | None = None) -> str:
    runtime_dir = str(_env("XDG_RUNTIME_DIR", "")).strip()
    base = runtime_dir or "/tmp"
    effective_port = int(port) if port is not None else PORT
    return str(Path(base) / "sniffhound" / f"capture-{effective_port}.sock")


def resolve_ipc_socket(port: int | None = None) -> str:
    override = str(_env("SNIFFHOUND_IPC_SOCKET", "")).strip()
    return override or default_ipc_socket_path(port)


def resolve_ipc_token() -> str:
    return str(_env("SNIFFHOUND_IPC_TOKEN", "")).strip()


def resolve_ipc_owner_uid() -> int | None:
    raw = str(_env("SNIFFHOUND_IPC_OWNER_UID", "")).strip()
    return int(raw) if raw.isdigit() else None


def resolve_ipc_connect_timeout() -> float:
    return max(1.0, _as_float(_env("SNIFFHOUND_IPC_CONNECT_TIMEOUT", "20"), 20.0))
