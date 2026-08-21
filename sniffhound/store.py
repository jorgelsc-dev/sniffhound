from __future__ import annotations

import ctypes
import ctypes.util
import ipaddress
import json
import sqlite3
import threading
from collections import Counter, defaultdict
from pathlib import Path

from .runtime_paths import ensure_data_dir, resolve_data_file
from .monitors import describe_match, load_builtin_monitors, normalize_monitor
from .rulesets import load_builtin_rulesets, normalize_ruleset
from .settings import MONITOR_FILTER_DEFAULT, PAYLOAD_TEXT_MAX_CHARS
from .utils import (
    bytes_to_hex_preview,
    bytes_to_text_preview,
    clamp_int,
    json_dumps,
    json_loads,
    local_ip_candidates,
    normalize_protocol_name,
    normalize_text,
    safe_float,
    safe_int,
    stable_flow_key,
    utc_now,
)


PACKET_TABLE_LIMIT = 2000
PAYLOAD_TABLE_LIMIT = 2000
FLOW_TABLE_LIMIT = 2000
TAG_TABLE_LIMIT = 4000
DOMAIN_TABLE_LIMIT = 5000
PATH_TABLE_LIMIT = 5000
_GEOIP_COUNTRY_DB_PATHS = (
    Path("/usr/share/GeoIP/GeoIP.dat"),
    Path("/usr/local/share/GeoIP/GeoIP.dat"),
)
_GEOIP_COUNTRY_V6_DB_PATHS = (
    Path("/usr/share/GeoIP/GeoIPv6.dat"),
    Path("/usr/local/share/GeoIP/GeoIPv6.dat"),
)
_ZONEINFO_COUNTRY_PATHS = (
    Path("/usr/share/zoneinfo/zone1970.tab"),
    Path("/usr/share/zoneinfo/zone.tab"),
)


def _row_to_dict(row, columns=None):
    if row is None:
        return None
    if columns:
        data = {column: value for column, value in zip(columns, tuple(row))}
    elif isinstance(row, dict):
        data = dict(row)
    elif hasattr(row, "keys"):
        keys = list(row.keys())
        data = {column: value for column, value in zip(keys, tuple(row))}
    else:
        data = dict(row)
    for key, value in list(data.items()):
        if isinstance(value, (bytes, bytearray, memoryview)):
            data[key] = bytes_to_hex_preview(bytes(value))
    return data


def _sqlite_text_factory(value):
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).decode("utf-8", errors="replace")
    return str(value)


def _coerce_json(value, default):
    if isinstance(value, (dict, list, tuple)):
        return value
    return json_loads(value, default=default)


def _ip_scope(ip: str) -> str:
    text = str(ip or "").strip()
    if not text:
        return "unknown"
    try:
        ip_obj = ipaddress.ip_address(text)
    except Exception:
        return "unknown"
    if ip_obj.is_loopback:
        return "local"
    if ip_obj.is_multicast:
        return "multicast"
    if ip_obj.is_private or ip_obj.is_link_local:
        return "private"
    if getattr(ip_obj, "is_reserved", False) or getattr(ip_obj, "is_unspecified", False):
        return "reserved"
    if ip_obj.is_global:
        return "public"
    return "private"


def _soc_ip_scope(ip: str) -> str:
    return _ip_scope(ip)


def _parse_iso6709_component(value: str) -> float | None:
    text = str(value or "").strip()
    if not text or text[0] not in "+-":
        return None
    sign = -1.0 if text[0] == "-" else 1.0
    digits = text[1:]
    if len(digits) not in (4, 5, 6, 7) or not digits.isdigit():
        return None
    degree_len = 2 if len(digits) in (4, 6) else 3
    degree = int(digits[:degree_len])
    minute = int(digits[degree_len : degree_len + 2])
    second = int(digits[degree_len + 2 : degree_len + 4]) if len(digits) > degree_len + 2 else 0
    return sign * (degree + (minute / 60.0) + (second / 3600.0))


def _parse_iso6709_pair(value: str) -> tuple[float | None, float | None]:
    text = str(value or "").strip()
    if not text:
        return None, None
    split_at = -1
    for index in range(1, len(text)):
        if text[index] in "+-":
            split_at = index
            break
    if split_at <= 0:
        return None, None
    return _parse_iso6709_component(text[:split_at]), _parse_iso6709_component(text[split_at:])


def _load_country_centroids() -> dict[str, dict[str, float]]:
    buckets: dict[str, list[float]] = {}
    for path in _ZONEINFO_COUNTRY_PATHS:
        if not path.exists():
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception:
            continue
        for line in lines:
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) < 3:
                continue
            countries = [item.strip().upper() for item in parts[0].split(",") if item.strip()]
            lat, lon = _parse_iso6709_pair(parts[1])
            if lat is None or lon is None:
                continue
            for country_code in countries:
                bucket = buckets.setdefault(country_code, [0.0, 0.0, 0.0])
                bucket[0] += lat
                bucket[1] += lon
                bucket[2] += 1.0
        break
    centroids = {}
    for country_code, values in buckets.items():
        count = values[2] or 1.0
        centroids[country_code] = {
            "lat": round(values[0] / count, 6),
            "lon": round(values[1] / count, 6),
        }
    return centroids


class _GeoCountryResolver:
    def __init__(self):
        self._lock = threading.RLock()
        self._cache: dict[str, dict] = {}
        self._centroids = _load_country_centroids()
        self._lib = None
        self._db_v4 = None
        self._db_v6 = None
        self._load_library()

    def _load_library(self):
        library_name = ctypes.util.find_library("GeoIP")
        if not library_name:
            return
        try:
            self._lib = ctypes.CDLL(library_name)
        except Exception:
            self._lib = None
            return
        self._lib.GeoIP_open.argtypes = [ctypes.c_char_p, ctypes.c_int]
        self._lib.GeoIP_open.restype = ctypes.c_void_p
        self._lib.GeoIP_delete.argtypes = [ctypes.c_void_p]
        self._lib.GeoIP_delete.restype = None
        self._lib.GeoIP_country_code_by_addr.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        self._lib.GeoIP_country_code_by_addr.restype = ctypes.c_char_p
        self._lib.GeoIP_country_name_by_addr.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        self._lib.GeoIP_country_name_by_addr.restype = ctypes.c_char_p
        if hasattr(self._lib, "GeoIP_country_code_by_addr_v6"):
            self._lib.GeoIP_country_code_by_addr_v6.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
            self._lib.GeoIP_country_code_by_addr_v6.restype = ctypes.c_char_p
        if hasattr(self._lib, "GeoIP_country_name_by_addr_v6"):
            self._lib.GeoIP_country_name_by_addr_v6.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
            self._lib.GeoIP_country_name_by_addr_v6.restype = ctypes.c_char_p
        self._db_v4 = self._open_database(_GEOIP_COUNTRY_DB_PATHS)
        self._db_v6 = self._open_database(_GEOIP_COUNTRY_V6_DB_PATHS)

    def _open_database(self, paths: tuple[Path, ...]):
        if not self._lib:
            return None
        for path in paths:
            if not path.exists():
                continue
            try:
                handle = self._lib.GeoIP_open(str(path).encode("utf-8"), 0)
            except Exception:
                handle = None
            if handle:
                return handle
        return None

    def describe_source(self) -> str:
        if (self._db_v4 or self._db_v6) and self._centroids:
            return "country-db-zoneinfo"
        if self._db_v4 or self._db_v6:
            return "country-db"
        return "empty"

    def lookup(self, ip: str) -> dict:
        text = str(ip or "").strip()
        if not text:
            return {}
        cached = self._cache.get(text)
        if cached is not None:
            return dict(cached)
        try:
            ip_obj = ipaddress.ip_address(text)
        except Exception:
            return {}

        country_code = ""
        country_name = ""
        encoded = text.encode("utf-8", errors="ignore")
        with self._lock:
            if ip_obj.version == 6 and self._db_v6 and hasattr(self._lib, "GeoIP_country_code_by_addr_v6"):
                raw_code = self._lib.GeoIP_country_code_by_addr_v6(self._db_v6, encoded)
                raw_name = self._lib.GeoIP_country_name_by_addr_v6(self._db_v6, encoded)
            elif self._db_v4:
                raw_code = self._lib.GeoIP_country_code_by_addr(self._db_v4, encoded)
                raw_name = self._lib.GeoIP_country_name_by_addr(self._db_v4, encoded)
            else:
                raw_code = None
                raw_name = None
        if raw_code:
            try:
                country_code = raw_code.decode("utf-8", errors="ignore").strip().upper()
            except Exception:
                country_code = ""
        if raw_name:
            try:
                country_name = raw_name.decode("utf-8", errors="ignore").strip()
            except Exception:
                country_name = ""

        centroid = self._centroids.get(country_code or "")
        result = {
            "found": bool(country_code),
            "country_code": country_code,
            "country": country_name,
            "lat": centroid.get("lat") if centroid else None,
            "lon": centroid.get("lon") if centroid else None,
            "precision": "country" if centroid else "",
            "source": self.describe_source(),
        }
        self._cache[text] = dict(result)
        return result

    def close(self):
        with self._lock:
            for handle in (self._db_v4, self._db_v6):
                if handle and self._lib:
                    try:
                        self._lib.GeoIP_delete(handle)
                    except Exception:
                        pass
            self._db_v4 = None
            self._db_v6 = None


def _soc_payload_signature(text: str) -> str:
    raw = str(text or "").strip()
    if not raw:
        return "empty"
    lowered = raw.lower()
    if raw.startswith("{") or raw.startswith("[") or '"type":' in lowered or '"packet"' in lowered:
        return "structured"
    if lowered.startswith("get ") or lowered.startswith("post ") or "http/" in lowered:
        return "http-like"
    alnum_space = sum(ch.isalnum() or ch.isspace() for ch in raw)
    symbol_ratio = 1 - (alnum_space / max(1, len(raw)))
    if symbol_ratio > 0.32 or (len(raw) > 80 and raw.count(" ") < len(raw) * 0.18):
        return "noisy"
    return "text"


class SniffStore:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        if not self.path.is_absolute():
            self.path = Path.cwd() / self.path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.text_factory = _sqlite_text_factory
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._geoip_resolver = _GeoCountryResolver()
        self._create_schema()
        self._seed_baseline()

    @property
    def local_ips(self) -> set[str]:
        return local_ip_candidates()

    def _create_schema(self):
        schema = [
            """
            CREATE TABLE IF NOT EXISTS sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                network TEXT NOT NULL,
                type TEXT NOT NULL,
                proto TEXT NOT NULL,
                port_mode TEXT NOT NULL,
                port_start INTEGER NOT NULL DEFAULT 0,
                port_end INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'stopped',
                timesleep REAL NOT NULL DEFAULT 0.5,
                progress REAL NOT NULL DEFAULT 0.0,
                interface TEXT NOT NULL DEFAULT '',
                filter_text TEXT NOT NULL DEFAULT '',
                packets_seen INTEGER NOT NULL DEFAULT 0,
                bytes_seen INTEGER NOT NULL DEFAULT 0,
                rules_seen INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS flows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                flow_key TEXT NOT NULL UNIQUE,
                proto TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                dst_ip TEXT NOT NULL,
                src_port INTEGER NOT NULL DEFAULT 0,
                dst_port INTEGER NOT NULL DEFAULT 0,
                packet_count INTEGER NOT NULL DEFAULT 0,
                byte_count INTEGER NOT NULL DEFAULT 0,
                state TEXT NOT NULL DEFAULT 'open',
                scan_state TEXT NOT NULL DEFAULT 'active',
                banner_text TEXT NOT NULL DEFAULT '',
                tags_json TEXT NOT NULL DEFAULT '[]',
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS packets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER NOT NULL DEFAULT 0,
                flow_key TEXT NOT NULL DEFAULT '',
                interface TEXT NOT NULL DEFAULT '',
                direction TEXT NOT NULL DEFAULT 'unknown',
                eth_src TEXT NOT NULL DEFAULT '',
                eth_dst TEXT NOT NULL DEFAULT '',
                eth_type INTEGER NOT NULL DEFAULT 0,
                ip_version INTEGER NOT NULL DEFAULT 0,
                src_ip TEXT NOT NULL DEFAULT '',
                dst_ip TEXT NOT NULL DEFAULT '',
                proto TEXT NOT NULL DEFAULT 'unknown',
                src_port INTEGER NOT NULL DEFAULT 0,
                dst_port INTEGER NOT NULL DEFAULT 0,
                ttl INTEGER NOT NULL DEFAULT 0,
                hop_limit INTEGER NOT NULL DEFAULT 0,
                length INTEGER NOT NULL DEFAULT 0,
                payload_len INTEGER NOT NULL DEFAULT 0,
                state TEXT NOT NULL DEFAULT 'open',
                scan_state TEXT NOT NULL DEFAULT 'active',
                tcp_flags TEXT NOT NULL DEFAULT '',
                icmp_type INTEGER NOT NULL DEFAULT 0,
                icmp_code INTEGER NOT NULL DEFAULT 0,
                arp_opcode INTEGER NOT NULL DEFAULT 0,
                summary TEXT NOT NULL DEFAULT '',
                payload_text TEXT NOT NULL DEFAULT '',
                payload_hex TEXT NOT NULL DEFAULT '',
                banner_text TEXT NOT NULL DEFAULT '',
                domain TEXT NOT NULL DEFAULT '',
                domain_source TEXT NOT NULL DEFAULT '',
                http_method TEXT NOT NULL DEFAULT '',
                http_path TEXT NOT NULL DEFAULT '',
                http_host TEXT NOT NULL DEFAULT '',
                tags_json TEXT NOT NULL DEFAULT '[]',
                rule_hits_json TEXT NOT NULL DEFAULT '[]',
                raw_packet BLOB,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS payloads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                packet_id INTEGER NOT NULL,
                flow_key TEXT NOT NULL DEFAULT '',
                ip TEXT NOT NULL DEFAULT '',
                port INTEGER NOT NULL DEFAULT 0,
                proto TEXT NOT NULL DEFAULT 'unknown',
                response_plain TEXT NOT NULL DEFAULT '',
                response_size INTEGER NOT NULL DEFAULT 0,
                scan_state TEXT NOT NULL DEFAULT 'active',
                port_id INTEGER NOT NULL DEFAULT 0,
                favicon_id INTEGER NOT NULL DEFAULT 0,
                state TEXT NOT NULL DEFAULT 'open',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS tags (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                packet_id INTEGER NOT NULL,
                flow_key TEXT NOT NULL DEFAULT '',
                ip TEXT NOT NULL DEFAULT '',
                port INTEGER NOT NULL DEFAULT 0,
                proto TEXT NOT NULL DEFAULT 'unknown',
                key TEXT NOT NULL DEFAULT '',
                value TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS rulesets (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                enabled INTEGER NOT NULL DEFAULT 1,
                priority INTEGER NOT NULL DEFAULT 100,
                source TEXT NOT NULL DEFAULT 'custom',
                match_json TEXT NOT NULL DEFAULT '{}',
                action_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS runtime_config (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL DEFAULT '',
                updated_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS domains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                source TEXT NOT NULL DEFAULT '',
                ip TEXT NOT NULL DEFAULT '',
                port INTEGER NOT NULL DEFAULT 0,
                proto TEXT NOT NULL DEFAULT '',
                hit_count INTEGER NOT NULL DEFAULT 1,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS paths (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT NOT NULL,
                method TEXT NOT NULL DEFAULT 'GET',
                host TEXT NOT NULL DEFAULT '',
                ip TEXT NOT NULL DEFAULT '',
                port INTEGER NOT NULL DEFAULT 0,
                hit_count INTEGER NOT NULL DEFAULT 1,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(method, path, host)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS monitors (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                enabled INTEGER NOT NULL DEFAULT 1,
                priority INTEGER NOT NULL DEFAULT 100,
                source TEXT NOT NULL DEFAULT 'custom',
                mode TEXT NOT NULL DEFAULT 'rule',
                match_json TEXT NOT NULL DEFAULT '{}',
                action_json TEXT NOT NULL DEFAULT '{}',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS honeypot_listeners (
                id TEXT PRIMARY KEY,
                proto TEXT NOT NULL,
                port INTEGER NOT NULL,
                label TEXT NOT NULL DEFAULT '',
                enabled INTEGER NOT NULL DEFAULT 1,
                source TEXT NOT NULL DEFAULT 'builtin',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """,
        ]
        with self._lock:
            for statement in schema:
                self._conn.execute(statement)
            self._conn.commit()
            self._migrate_packets_columns()

    def _migrate_packets_columns(self):
        existing = {row["name"] for row in self._conn.execute("PRAGMA table_info(packets)")}
        additions = {
            "domain": "TEXT NOT NULL DEFAULT ''",
            "domain_source": "TEXT NOT NULL DEFAULT ''",
            "http_method": "TEXT NOT NULL DEFAULT ''",
            "http_path": "TEXT NOT NULL DEFAULT ''",
            "http_host": "TEXT NOT NULL DEFAULT ''",
        }
        for column, definition in additions.items():
            if column not in existing:
                self._conn.execute(f"ALTER TABLE packets ADD COLUMN {column} {definition}")
        self._conn.commit()

    def _seed_baseline(self):
        with self._lock:
            cursor = self._conn.execute("SELECT COUNT(*) AS count FROM rulesets")
            count = int(cursor.fetchone()["count"] or 0)
            if count == 0:
                now = utc_now()
                for rule in load_builtin_rulesets():
                    self._conn.execute(
                        """
                        INSERT OR REPLACE INTO rulesets
                        (id, name, description, enabled, priority, source, match_json, action_json, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            str(rule.get("id") or rule.get("name")),
                            str(rule.get("name") or rule.get("id")),
                            str(rule.get("description") or ""),
                            1 if rule.get("enabled", True) else 0,
                            safe_int(rule.get("priority", 100), 100),
                            str(rule.get("source") or "builtin"),
                            json_dumps(rule.get("match") or {}),
                            json_dumps(rule.get("action") or {}),
                            now,
                            now,
                        ),
                    )
                self._conn.commit()

            cursor = self._conn.execute("SELECT COUNT(*) AS count FROM monitors")
            count = int(cursor.fetchone()["count"] or 0)
            if count == 0:
                now = utc_now()
                rows = [
                    (
                        str(monitor.get("id") or monitor.get("name")),
                        str(monitor.get("name") or monitor.get("id")),
                        str(monitor.get("description") or ""),
                        1 if monitor.get("enabled", True) else 0,
                        safe_int(monitor.get("priority", 100), 100),
                        str(monitor.get("source") or "builtin"),
                        str(monitor.get("mode") or "rule"),
                        json_dumps(monitor.get("match") or {}),
                        json_dumps(monitor.get("action") or {}),
                        now,
                        now,
                    )
                    for monitor in load_builtin_monitors()
                ]
                self._conn.executemany(
                    """
                    INSERT OR REPLACE INTO monitors
                    (id, name, description, enabled, priority, source, mode, match_json, action_json, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    rows,
                )
                self._conn.commit()

            self._seed_new_builtin_monitors()

        self._seed_file_catalogs()
        self._seed_builtin_honeypot_listeners()

    def _seed_builtin_honeypot_listeners(self):
        """Additive migration, same shape as `_seed_new_builtin_monitors`:
        insert any built-in listener (from `honeypot.COMMON_PORTS`) that
        isn't already in the table, by id, without touching any existing
        row - so a listener the user has since disabled stays disabled
        across restarts, and a new port added to COMMON_PORTS in a later
        release still reaches already-populated databases."""
        from .honeypot_ports import COMMON_PORTS

        cursor = self._conn.execute("SELECT id FROM honeypot_listeners")
        existing_ids = {str(row["id"]) for row in cursor.fetchall()}
        now = utc_now()
        inserted = False
        for proto in ("tcp", "udp"):
            for port in COMMON_PORTS.get(proto, ()):
                listener_id = f"{proto}/{port}"
                if listener_id in existing_ids:
                    continue
                self._conn.execute(
                    """
                    INSERT OR IGNORE INTO honeypot_listeners
                    (id, proto, port, label, enabled, source, created_at, updated_at)
                    VALUES (?, ?, ?, '', 1, 'builtin', ?, ?)
                    """,
                    (listener_id, proto, int(port), now, now),
                )
                inserted = True
        if inserted:
            self._conn.commit()

    def list_honeypot_listeners(self):
        rows = self._fetchall("SELECT * FROM honeypot_listeners ORDER BY proto ASC, port ASC")
        for row in rows:
            row["enabled"] = bool(row.get("enabled"))
        return rows

    def get_honeypot_listener(self, listener_id: str):
        row = self._fetchone("SELECT * FROM honeypot_listeners WHERE id = ?", (str(listener_id),))
        if not row:
            return None
        row["enabled"] = bool(row.get("enabled"))
        return row

    def create_honeypot_listener(self, proto: str, port: int, label: str = ""):
        proto = str(proto or "").strip().lower()
        if proto not in ("tcp", "udp"):
            raise ValueError("proto must be 'tcp' or 'udp'")
        port = safe_int(port, 0)
        if port < 1 or port > 65535:
            raise ValueError("port must be between 1 and 65535")
        listener_id = f"{proto}/{port}"
        if self.get_honeypot_listener(listener_id):
            raise ValueError(f"Listener {listener_id} already exists")
        now = utc_now()
        self._execute(
            """
            INSERT INTO honeypot_listeners (id, proto, port, label, enabled, source, created_at, updated_at)
            VALUES (?, ?, ?, ?, 1, 'custom', ?, ?)
            """,
            (listener_id, proto, port, str(label or ""), now, now),
            commit=True,
        )
        return self.get_honeypot_listener(listener_id)

    def set_honeypot_listener_enabled(self, listener_id: str, enabled: bool):
        """Flip a listener's `enabled` flag only - this is the *only* way to
        change any listener after creation, builtin or custom alike; there
        is deliberately no edit/delete path (see honeypot.py's HoneypotView
        docs) so the historical record of what was ever exposed stays intact."""
        existing = self.get_honeypot_listener(listener_id)
        if not existing:
            raise ValueError(f"Unknown listener id: {listener_id}")
        now = utc_now()
        self._execute(
            "UPDATE honeypot_listeners SET enabled = ?, updated_at = ? WHERE id = ?",
            (1 if enabled else 0, now, str(listener_id)),
            commit=True,
        )
        return self.get_honeypot_listener(listener_id)

    def _seed_new_builtin_monitors(self):
        """Additive + pruning + definition-sync migration, run on every
        startup (not just against a brand new DB - see the `count == 0`
        seeding above):

        - Insert any catalog id that isn't already in the table, by id,
          without touching any existing row - so monitors added in a later
          release reach already-populated databases too.
        - Remove any *builtin* row whose id is no longer in the current
          catalog. The bundled catalog can and does change between
          releases as quality filters improve (a pattern
          that turned out to be a false-positive magnet, or too broad to
          be a meaningful signature at all) - without this, a row seeded by
          an earlier, broader catalog would sit in the table and keep
          matching live traffic forever, since a plain additive migration
          only ever adds. Already-stored packets/tags that reference a
          pruned id are untouched (they're the historical record of what
          it once flagged); only the live definition goes away.
        - Sync name/description/priority/mode/match_json/action_json for
          any *builtin* row whose catalog definition changed since it was
          seeded (e.g. a false-positive-prone regex/content literal
          tightened, or a severity re-classified by the native catalog
          builder). Deliberately leaves
          `enabled` untouched: that's the one field a user can have
          manually flipped (via /api/monitors/toggle) on a builtin
          monitor, and a catalog update must never silently re-enable or
          re-disable a row the user already made a call on. Only a fix
          that ships as a *removed* id (handled by the pruning step above)
          can retroactively force a monitor off.

        Never touches a `source = 'custom'` row for either the delete or
        the sync - a user's own monitor is never in the bundled catalog
        to begin with, so it can't collide, but both are still scoped to
        `source = 'builtin'` as a second guard.
        """
        cursor = self._conn.execute(
            "SELECT id, source, name, description, priority, mode, match_json, action_json FROM monitors"
        )
        existing_rows = {str(row["id"]): dict(row) for row in cursor.fetchall()}

        catalog = load_builtin_monitors()
        catalog_ids = {str(monitor.get("id") or "").strip() for monitor in catalog if monitor.get("id")}

        now = utc_now()
        insert_rows = []
        update_rows = []
        for monitor in catalog:
            monitor_id = str(monitor.get("id") or "").strip()
            if not monitor_id:
                continue
            name = str(monitor.get("name") or monitor_id)
            description = str(monitor.get("description") or "")
            priority = safe_int(monitor.get("priority", 100), 100)
            mode = str(monitor.get("mode") or "rule")
            match_json = json_dumps(monitor.get("match") or {})
            action_json = json_dumps(monitor.get("action") or {})

            existing = existing_rows.get(monitor_id)
            if existing is None:
                insert_rows.append(
                    (
                        monitor_id,
                        name,
                        description,
                        1 if monitor.get("enabled", True) else 0,
                        priority,
                        str(monitor.get("source") or "builtin"),
                        mode,
                        match_json,
                        action_json,
                        now,
                        now,
                    )
                )
                continue
            if existing.get("source") != "builtin":
                continue
            if (
                existing.get("name") == name
                and existing.get("description") == description
                and safe_int(existing.get("priority"), 100) == priority
                and existing.get("mode") == mode
                and existing.get("match_json") == match_json
                and existing.get("action_json") == action_json
            ):
                continue
            update_rows.append((name, description, priority, mode, match_json, action_json, now, monitor_id))

        if insert_rows:
            # executemany() over one prepared statement instead of one
            # execute() call per row - with thousands of builtin monitors
            # this migration runs on every single startup (not just the first), so the
            # per-statement overhead of a Python-level loop adds up fast.
            self._conn.executemany(
                """
                INSERT OR IGNORE INTO monitors
                (id, name, description, enabled, priority, source, mode, match_json, action_json, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                insert_rows,
            )
        if update_rows:
            self._conn.executemany(
                """
                UPDATE monitors
                SET name = ?, description = ?, priority = ?, mode = ?, match_json = ?, action_json = ?, updated_at = ?
                WHERE id = ? AND source = 'builtin'
                """,
                update_rows,
            )

        stale_builtin_ids = [
            monitor_id
            for monitor_id, row in existing_rows.items()
            if row.get("source") == "builtin" and monitor_id not in catalog_ids
        ]
        if stale_builtin_ids:
            placeholders = ",".join("?" for _ in stale_builtin_ids)
            self._conn.execute(
                f"DELETE FROM monitors WHERE source = 'builtin' AND id IN ({placeholders})",
                stale_builtin_ids,
            )

        if insert_rows or update_rows or stale_builtin_ids:
            self._conn.commit()

    def _seed_file_catalogs(self):
        catalogs = {
            "banner_regex_rules.json": load_builtin_rulesets(),
            "banner_probe_requests.json": [
                {
                    "id": "http-get",
                    "name": "HTTP GET",
                    "description": "Common HTTP request pattern for live payload previews.",
                    "enabled": True,
                    "priority": 10,
                    "match": {"protocols": ["tcp"], "payload_contains": ["GET "]},
                    "action": {"tag": "http-get", "label": "HTTP GET", "severity": "low"},
                },
                {
                    "id": "http-post",
                    "name": "HTTP POST",
                    "description": "Common HTTP POST payload pattern.",
                    "enabled": True,
                    "priority": 11,
                    "match": {"protocols": ["tcp"], "payload_contains": ["POST "]},
                    "action": {"tag": "http-post", "label": "HTTP POST", "severity": "low"},
                },
            ],
            "ip_presets.json": [
                {
                    "id": "all-interfaces",
                    "name": "All interfaces",
                    "description": "Watch every visible interface and store every observed packet.",
                    "interface": "",
                    "network": "0.0.0.0/0",
                    "proto": "all",
                    "port_mode": "preset",
                    "port_start": 0,
                    "port_end": 0,
                },
                {
                    "id": "loopback",
                    "name": "Loopback",
                    "description": "Useful local-development preset.",
                    "interface": "lo",
                    "network": "127.0.0.0/8",
                    "proto": "tcp",
                    "port_mode": "preset",
                    "port_start": 0,
                    "port_end": 0,
                },
            ],
        }
        for filename, payload in catalogs.items():
            path = resolve_data_file(filename)
            if path.exists():
                continue
            try:
                path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
            except Exception:
                pass

    def close(self):
        with self._lock:
            try:
                self._geoip_resolver.close()
            except Exception:
                pass
            try:
                self._conn.close()
            except Exception:
                pass

    def _execute(self, sql, params=(), *, commit=False):
        with self._lock:
            cursor = self._conn.execute(sql, params)
            if commit:
                self._conn.commit()
            return cursor

    def _fetchall(self, sql, params=()):
        cursor = self._execute(sql, params)
        columns = [column[0] for column in (cursor.description or ())]
        return [_row_to_dict(row, columns=columns) for row in cursor.fetchall()]

    def _fetchone(self, sql, params=()):
        cursor = self._execute(sql, params)
        columns = [column[0] for column in (cursor.description or ())]
        return _row_to_dict(cursor.fetchone(), columns=columns)

    def _ensure_session(self, session_id: int):
        if session_id and self._fetchone("SELECT id FROM sessions WHERE id = ?", (session_id,)):
            return int(session_id)
        now = utc_now()
        cursor = self._execute(
            """
            INSERT INTO sessions
            (network, type, proto, port_mode, port_start, port_end, status, timesleep, progress, interface,
             filter_text, packets_seen, bytes_seen, rules_seen, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 0, ?, ?)
            """,
            (
                "0.0.0.0/0",
                "all",
                "all",
                "preset",
                0,
                0,
                "active",
                0.5,
                0.0,
                "",
                "",
                now,
                now,
            ),
            commit=True,
        )
        return int(cursor.lastrowid)

    def create_session(self, data: dict) -> dict:
        now = utc_now()
        payload = {
            "network": str(data.get("network") or "0.0.0.0/0").strip() or "0.0.0.0/0",
            "type": str(data.get("type") or "all").strip() or "all",
            "proto": normalize_protocol_name(data.get("proto") or "all"),
            "port_mode": str(data.get("port_mode") or "preset").strip().lower() or "preset",
            "port_start": safe_int(data.get("port_start", data.get("port")), 0),
            "port_end": safe_int(data.get("port_end", data.get("port")), 0),
            "status": str(data.get("status") or "stopped").strip().lower() or "stopped",
            "timesleep": safe_float(data.get("timesleep", 0.5), 0.5),
            "progress": safe_float(data.get("progress", 0.0), 0.0),
            "interface": str(data.get("interface") or "").strip(),
            "filter_text": str(data.get("filter_text") or "").strip(),
        }
        if payload["port_mode"] not in {"preset", "single", "range"}:
            payload["port_mode"] = "preset"
        if payload["status"] not in {"active", "stopped", "restarting"}:
            payload["status"] = "stopped"
        with self._lock:
            cursor = self._conn.execute(
                """
                INSERT INTO sessions
                (network, type, proto, port_mode, port_start, port_end, status, timesleep, progress, interface,
                 filter_text, packets_seen, bytes_seen, rules_seen, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 0, ?, ?)
                """,
                (
                    payload["network"],
                    payload["type"],
                    payload["proto"],
                    payload["port_mode"],
                    payload["port_start"],
                    payload["port_end"],
                    payload["status"],
                    payload["timesleep"],
                    payload["progress"],
                    payload["interface"],
                    payload["filter_text"],
                    now,
                    now,
                ),
            )
            self._conn.commit()
            return self.get_session(cursor.lastrowid)

    def update_session(self, session_id: int, data: dict) -> dict | None:
        existing = self.get_session(session_id)
        if not existing:
            return None
        updated = {
            "network": str(data.get("network", existing["network"])).strip() or existing["network"],
            "type": str(data.get("type", existing["type"])).strip() or existing["type"],
            "proto": normalize_protocol_name(data.get("proto", existing["proto"])),
            "port_mode": str(data.get("port_mode", existing["port_mode"])).strip().lower() or existing["port_mode"],
            "port_start": safe_int(data.get("port_start", existing["port_start"]), existing["port_start"]),
            "port_end": safe_int(data.get("port_end", existing["port_end"]), existing["port_end"]),
            "status": str(data.get("status", existing["status"])).strip().lower() or existing["status"],
            "timesleep": safe_float(data.get("timesleep", existing["timesleep"]), existing["timesleep"]),
            "progress": safe_float(data.get("progress", existing["progress"]), existing["progress"]),
            "interface": str(data.get("interface", existing["interface"])).strip(),
            "filter_text": str(data.get("filter_text", existing["filter_text"])).strip(),
        }
        if updated["port_mode"] not in {"preset", "single", "range"}:
            updated["port_mode"] = existing["port_mode"]
        if updated["status"] not in {"active", "stopped", "restarting"}:
            updated["status"] = existing["status"]
        now = utc_now()
        self._execute(
            """
            UPDATE sessions
            SET network = ?, type = ?, proto = ?, port_mode = ?, port_start = ?, port_end = ?,
                status = ?, timesleep = ?, progress = ?, interface = ?, filter_text = ?, updated_at = ?
            WHERE id = ?
            """,
            (
                updated["network"],
                updated["type"],
                updated["proto"],
                updated["port_mode"],
                updated["port_start"],
                updated["port_end"],
                updated["status"],
                updated["timesleep"],
                updated["progress"],
                updated["interface"],
                updated["filter_text"],
                now,
                session_id,
            ),
            commit=True,
        )
        return self.get_session(session_id)

    def delete_session(self, session_id: int) -> bool:
        with self._lock:
            self._conn.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
            self._conn.commit()
        return True

    def set_session_status(self, session_id: int, status: str, *, progress: float | None = None):
        status = str(status or "").strip().lower() or "stopped"
        if status not in {"active", "stopped", "restarting"}:
            status = "stopped"
        updates = ["status = ?", "updated_at = ?"]
        values = [status, utc_now()]
        if progress is not None:
            updates.insert(0, "progress = ?")
            values.insert(0, float(progress))
        values.append(session_id)
        self._execute(
            f"UPDATE sessions SET {', '.join(updates)} WHERE id = ?",
            tuple(values),
            commit=True,
        )
        return self.get_session(session_id)

    def bump_session_counters(self, session_id: int, packet_length: int, rule_count: int):
        session_id = self._ensure_session(session_id)
        now = utc_now()
        with self._lock:
            self._conn.execute(
                """
                UPDATE sessions
                SET packets_seen = packets_seen + 1,
                    bytes_seen = bytes_seen + ?,
                    rules_seen = rules_seen + ?,
                    progress = MIN(100.0, progress + 0.25),
                    updated_at = ?
                WHERE id = ?
                """,
                (int(packet_length), int(rule_count), now, session_id),
            )
            self._conn.commit()

    def get_session(self, session_id: int):
        return self._fetchone("SELECT * FROM sessions WHERE id = ?", (session_id,))

    def list_sessions(self, *, limit=200, offset=0, search="", proto=""):
        clauses = []
        params = []
        if proto:
            clauses.append("LOWER(proto) = ?")
            params.append(normalize_protocol_name(proto))
        if search:
            needle = f"%{str(search).strip().lower()}%"
            clauses.append(
                "("
                "LOWER(network) LIKE ? OR LOWER(type) LIKE ? OR LOWER(proto) LIKE ? "
                "OR LOWER(status) LIKE ? OR LOWER(interface) LIKE ? OR LOWER(filter_text) LIKE ?"
                ")"
            )
            params.extend([needle] * 6)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.extend([int(limit), int(offset)])
        return self._fetchall(
            f"SELECT * FROM sessions {where} ORDER BY id DESC LIMIT ? OFFSET ?",
            tuple(params),
        )

    def list_protocols(self):
        rows = self._fetchall("SELECT DISTINCT proto FROM packets ORDER BY proto ASC")
        protocols = [normalize_protocol_name(row["proto"]) for row in rows if row.get("proto")]
        if not protocols:
            protocols = ["arp", "icmp", "icmpv6", "sctp", "stp", "tcp", "udp", "ipv6", "unknown"]
        return sorted(set(protocols))

    def list_packets(self, *, proto="", session_id=0, search="", interface="", mode="", limit=250, offset=0):
        clauses = []
        params = []
        if proto:
            clauses.append("LOWER(proto) = ?")
            params.append(normalize_protocol_name(proto))
        if session_id:
            clauses.append("session_id = ?")
            params.append(int(session_id))
        interface_value = str(interface or "").strip().lower()
        if interface_value:
            if interface_value.endswith("*"):
                clauses.append("LOWER(interface) LIKE ?")
                params.append(f"{interface_value[:-1]}%")
            else:
                clauses.append("LOWER(interface) = ?")
                params.append(interface_value)
        mode_value = str(mode or "").strip().lower()
        if mode_value == "honeypot":
            clauses.append(
                "("
                "LOWER(interface) = 'honeypot' OR LOWER(interface) LIKE 'honeypot:%' OR "
                "LOWER(interface) = 'service' OR LOWER(interface) LIKE 'service:%'"
                ")"
            )
        elif mode_value == "sniffer":
            clauses.append(
                "("
                "LOWER(interface) != 'honeypot' AND LOWER(interface) NOT LIKE 'honeypot:%' AND "
                "LOWER(interface) != 'service' AND LOWER(interface) NOT LIKE 'service:%'"
                ")"
            )
        if search:
            needle = f"%{str(search).strip().lower()}%"
            clauses.append(
                "("
                "LOWER(src_ip) LIKE ? OR LOWER(dst_ip) LIKE ? OR LOWER(summary) LIKE ? OR "
                "LOWER(payload_text) LIKE ? OR LOWER(banner_text) LIKE ? OR LOWER(tags_json) LIKE ? OR "
                "LOWER(interface) LIKE ? OR LOWER(direction) LIKE ? OR CAST(src_port AS TEXT) LIKE ? OR CAST(dst_port AS TEXT) LIKE ?"
                ")"
            )
            params.extend([needle] * 10)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.extend([int(limit), int(offset)])
        return self._fetchall(
            f"SELECT * FROM packets {where} ORDER BY id DESC LIMIT ? OFFSET ?",
            tuple(params),
        )

    def list_packets_by_monitor(self, monitor_id: str, *, search="", limit=200, offset=0):
        clauses = ["tags.key = 'monitor_id'", "tags.value = ?"]
        params = [str(monitor_id)]
        if search:
            needle = f"%{str(search).strip().lower()}%"
            clauses.append(
                "("
                "LOWER(packets.src_ip) LIKE ? OR LOWER(packets.dst_ip) LIKE ? OR LOWER(packets.summary) LIKE ? OR "
                "LOWER(packets.payload_text) LIKE ? OR LOWER(packets.banner_text) LIKE ? OR "
                "CAST(packets.src_port AS TEXT) LIKE ? OR CAST(packets.dst_port AS TEXT) LIKE ?"
                ")"
            )
            params.extend([needle] * 7)
        where = f"WHERE {' AND '.join(clauses)}"
        params.extend([int(limit), int(offset)])
        rows = self._fetchall(
            f"""
            SELECT DISTINCT packets.*
            FROM packets
            JOIN tags ON tags.packet_id = packets.id
            {where}
            ORDER BY packets.id DESC
            LIMIT ? OFFSET ?
            """,
            tuple(params),
        )
        monitor = self.get_monitor(monitor_id)
        if monitor:
            for row in rows:
                row["matched_value"] = describe_match(monitor, row)
        else:
            for row in rows:
                row["matched_value"] = ""
        return rows

    def list_flows(self, *, proto="", search="", limit=250, offset=0):
        clauses = []
        params = []
        if proto:
            clauses.append("LOWER(proto) = ?")
            params.append(normalize_protocol_name(proto))
        if search:
            needle = f"%{str(search).strip().lower()}%"
            clauses.append(
                "("
                "LOWER(src_ip) LIKE ? OR LOWER(dst_ip) LIKE ? OR LOWER(flow_key) LIKE ? OR "
                "LOWER(banner_text) LIKE ? OR LOWER(tags_json) LIKE ?"
                ")"
            )
            params.extend([needle] * 5)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.extend([int(limit), int(offset)])
        return self._fetchall(
            f"SELECT * FROM flows {where} ORDER BY packet_count DESC, id DESC LIMIT ? OFFSET ?",
            tuple(params),
        )

    def list_payloads(self, *, search="", proto="", interface="", mode="", limit=250, offset=0):
        clauses = []
        params = []
        if proto:
            clauses.append("LOWER(payloads.proto) = ?")
            params.append(normalize_protocol_name(proto))
        interface_value = str(interface or "").strip().lower()
        if interface_value:
            if interface_value.endswith("*"):
                clauses.append("LOWER(COALESCE(p.interface, '')) LIKE ?")
                params.append(f"{interface_value[:-1]}%")
            else:
                clauses.append("LOWER(COALESCE(p.interface, '')) = ?")
                params.append(interface_value)
        mode_value = str(mode or "").strip().lower()
        if mode_value == "honeypot":
            clauses.append(
                "("
                "LOWER(COALESCE(p.interface, '')) = 'honeypot' OR LOWER(COALESCE(p.interface, '')) LIKE 'honeypot:%' OR "
                "LOWER(COALESCE(p.interface, '')) = 'service' OR LOWER(COALESCE(p.interface, '')) LIKE 'service:%'"
                ")"
            )
        elif mode_value == "sniffer":
            clauses.append(
                "("
                "LOWER(COALESCE(p.interface, '')) != 'honeypot' AND LOWER(COALESCE(p.interface, '')) NOT LIKE 'honeypot:%' AND "
                "LOWER(COALESCE(p.interface, '')) != 'service' AND LOWER(COALESCE(p.interface, '')) NOT LIKE 'service:%'"
                ")"
            )
        if search:
            needle = f"%{str(search).strip().lower()}%"
            clauses.append(
                "("
                "LOWER(payloads.response_plain) LIKE ? OR LOWER(payloads.ip) LIKE ? OR LOWER(payloads.proto) LIKE ? OR "
                "LOWER(COALESCE(p.interface, '')) LIKE ? OR LOWER(COALESCE(p.src_ip, '')) LIKE ? OR LOWER(COALESCE(p.dst_ip, '')) LIKE ? OR "
                "CAST(payloads.port AS TEXT) LIKE ? OR CAST(COALESCE(p.src_port, 0) AS TEXT) LIKE ? OR CAST(COALESCE(p.dst_port, 0) AS TEXT) LIKE ?"
                ")"
            )
            params.extend([needle] * 9)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.extend([int(limit), int(offset)])
        return self._fetchall(
            f"""
            SELECT
                payloads.*,
                p.session_id AS session_id,
                p.interface AS interface,
                p.direction AS direction,
                p.src_ip AS src_ip,
                p.dst_ip AS dst_ip,
                p.src_port AS src_port,
                p.dst_port AS dst_port,
                p.summary AS summary,
                p.tags_json AS tags_json
            FROM payloads
            LEFT JOIN packets AS p
                ON p.id = payloads.packet_id
            {where}
            ORDER BY payloads.id DESC
            LIMIT ? OFFSET ?
            """,
            tuple(params),
        )

    def list_tags(self, *, proto="", search="", limit=400, offset=0):
        clauses = []
        params = []
        if proto:
            clauses.append("LOWER(proto) = ?")
            params.append(normalize_protocol_name(proto))
        if search:
            needle = f"%{str(search).strip().lower()}%"
            clauses.append(
                "("
                "LOWER(ip) LIKE ? OR LOWER(key) LIKE ? OR LOWER(value) LIKE ? OR LOWER(flow_key) LIKE ?"
                ")"
            )
            params.extend([needle] * 4)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.extend([int(limit), int(offset)])
        return self._fetchall(
            f"SELECT * FROM tags {where} ORDER BY id DESC LIMIT ? OFFSET ?",
            tuple(params),
        )

    def record_domain(self, *, name: str, source: str = "", ip: str = "", port: int = 0, proto: str = ""):
        name = str(name or "").strip().lower()
        if not name:
            return None
        now = utc_now()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO domains (name, source, ip, port, proto, hit_count, first_seen, last_seen, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                  source = excluded.source,
                  ip = excluded.ip,
                  port = excluded.port,
                  proto = excluded.proto,
                  hit_count = hit_count + 1,
                  last_seen = excluded.last_seen,
                  updated_at = excluded.updated_at
                """,
                (name, str(source or ""), str(ip or ""), safe_int(port, 0), normalize_protocol_name(proto), now, now, now, now),
            )
            self._conn.commit()
        return self._fetchone("SELECT * FROM domains WHERE name = ?", (name,))

    def list_domains(self, *, search="", limit=200, offset=0):
        clauses = []
        params = []
        if search:
            needle = f"%{str(search).strip().lower()}%"
            clauses.append("(LOWER(name) LIKE ? OR LOWER(source) LIKE ? OR LOWER(ip) LIKE ?)")
            params.extend([needle] * 3)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.extend([int(limit), int(offset)])
        return self._fetchall(
            f"SELECT * FROM domains {where} ORDER BY last_seen DESC LIMIT ? OFFSET ?",
            tuple(params),
        )

    def record_path(self, *, path: str, method: str = "GET", host: str = "", ip: str = "", port: int = 0):
        path = str(path or "").strip()
        if not path:
            return None
        method = str(method or "GET").strip().upper() or "GET"
        host = str(host or "").strip().lower()
        now = utc_now()
        with self._lock:
            self._conn.execute(
                """
                INSERT INTO paths (path, method, host, ip, port, hit_count, first_seen, last_seen, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
                ON CONFLICT(method, path, host) DO UPDATE SET
                  ip = excluded.ip,
                  port = excluded.port,
                  hit_count = hit_count + 1,
                  last_seen = excluded.last_seen,
                  updated_at = excluded.updated_at
                """,
                (path, method, host, str(ip or ""), safe_int(port, 0), now, now, now, now),
            )
            self._conn.commit()
        return self._fetchone(
            "SELECT * FROM paths WHERE method = ? AND path = ? AND host = ?",
            (method, path, host),
        )

    def list_paths(self, *, search="", limit=200, offset=0):
        clauses = []
        params = []
        if search:
            needle = f"%{str(search).strip().lower()}%"
            clauses.append("(LOWER(path) LIKE ? OR LOWER(host) LIKE ? OR LOWER(method) LIKE ? OR LOWER(ip) LIKE ?)")
            params.extend([needle] * 4)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.extend([int(limit), int(offset)])
        return self._fetchall(
            f"SELECT * FROM paths {where} ORDER BY last_seen DESC LIMIT ? OFFSET ?",
            tuple(params),
        )

    def list_ip_catalog(self, *, search="", limit=200, offset=0):
        needle = f"%{str(search).strip().lower()}%" if search else ""
        where = "WHERE LOWER(ip) LIKE ?" if needle else ""
        params = [needle] if needle else []
        params.extend([int(limit), int(offset)])
        rows = self._fetchall(
            f"""
            SELECT
              ip,
              COUNT(*) AS hit_count,
              MIN(created_at) AS first_seen,
              MAX(created_at) AS last_seen
            FROM (
              SELECT src_ip AS ip, created_at FROM packets WHERE src_ip != ''
              UNION ALL
              SELECT dst_ip AS ip, created_at FROM packets WHERE dst_ip != ''
            )
            {where}
            GROUP BY ip
            ORDER BY last_seen DESC
            LIMIT ? OFFSET ?
            """,
            tuple(params),
        )
        for row in rows:
            ip = str(row.get("ip") or "")
            try:
                row["private"] = ipaddress.ip_address(ip).is_private
            except Exception:
                row["private"] = False
        return rows

    def list_rulesets(self):
        rows = self._fetchall("SELECT * FROM rulesets ORDER BY priority ASC, name ASC")
        for row in rows:
            row["match"] = _coerce_json(row.get("match_json"), {}) or {}
            row["action"] = _coerce_json(row.get("action_json"), {}) or {}
            row["enabled"] = bool(row.get("enabled"))
        return rows

    def get_ruleset(self, rule_id: str):
        row = self._fetchone("SELECT * FROM rulesets WHERE id = ?", (str(rule_id),))
        if not row:
            return None
        row["match"] = _coerce_json(row.get("match_json"), {}) or {}
        row["action"] = _coerce_json(row.get("action_json"), {}) or {}
        row["enabled"] = bool(row.get("enabled"))
        return row

    def save_ruleset(self, data: dict):
        normalized = normalize_ruleset(data, allow_source=True)
        rule_id = normalized["id"]
        existing = self.get_ruleset(rule_id)
        if existing and existing.get("source") == "builtin":
            raise ValueError("Builtin rulesets are read-only")
        now = utc_now()
        self._execute(
            """
            INSERT INTO rulesets (id, name, description, enabled, priority, source, match_json, action_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
              name = excluded.name,
              description = excluded.description,
              enabled = excluded.enabled,
              priority = excluded.priority,
              source = excluded.source,
              match_json = excluded.match_json,
              action_json = excluded.action_json,
              updated_at = excluded.updated_at
            """,
            (
                rule_id,
                normalized["name"],
                normalized.get("description", ""),
                1 if normalized.get("enabled", True) else 0,
                int(normalized.get("priority", 100)),
                str(normalized.get("source") or "custom"),
                json_dumps(normalized.get("match") or {}),
                json_dumps(normalized.get("action") or {}),
                now,
                now,
            ),
            commit=True,
        )
        return self.get_ruleset(rule_id)

    def delete_ruleset(self, rule_id: str):
        existing = self.get_ruleset(rule_id)
        if existing and existing.get("source") == "builtin":
            raise ValueError("Builtin rulesets are read-only")
        self._execute("DELETE FROM rulesets WHERE id = ?", (str(rule_id),), commit=True)
        return True

    def list_monitors(self):
        rows = self._fetchall("SELECT * FROM monitors ORDER BY priority ASC, name ASC")
        for row in rows:
            row["match"] = _coerce_json(row.get("match_json"), {}) or {}
            row["action"] = _coerce_json(row.get("action_json"), {}) or {}
            row["enabled"] = bool(row.get("enabled"))
        return rows

    def monitor_match_counts(self) -> dict:
        """Matched-packet count per monitor id, in one grouped query - not
        folded into list_monitors() itself since that's also polled every
        MONITOR_CACHE_TTL_SECONDS by the live capture path (Sniffer), which
        has no use for these counts and shouldn't pay for them."""
        rows = self._fetchall(
            """
            SELECT tags.value AS monitor_id, COUNT(DISTINCT tags.packet_id) AS count
            FROM tags
            WHERE tags.key = 'monitor_id'
            GROUP BY tags.value
            """
        )
        return {str(row["monitor_id"]): int(row["count"]) for row in rows}

    def get_monitor(self, monitor_id: str):
        row = self._fetchone("SELECT * FROM monitors WHERE id = ?", (str(monitor_id),))
        if not row:
            return None
        row["match"] = _coerce_json(row.get("match_json"), {}) or {}
        row["action"] = _coerce_json(row.get("action_json"), {}) or {}
        row["enabled"] = bool(row.get("enabled"))
        return row

    def save_monitor(self, data: dict):
        normalized = normalize_monitor(data, allow_source=True)
        monitor_id = normalized["id"]
        existing = self.get_monitor(monitor_id)
        if existing and existing.get("source") == "builtin":
            raise ValueError("Builtin monitors are read-only")
        now = utc_now()
        self._execute(
            """
            INSERT INTO monitors (id, name, description, enabled, priority, source, mode, match_json, action_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
              name = excluded.name,
              description = excluded.description,
              enabled = excluded.enabled,
              priority = excluded.priority,
              source = excluded.source,
              mode = excluded.mode,
              match_json = excluded.match_json,
              action_json = excluded.action_json,
              updated_at = excluded.updated_at
            """,
            (
                monitor_id,
                normalized["name"],
                normalized.get("description", ""),
                1 if normalized.get("enabled", True) else 0,
                int(normalized.get("priority", 100)),
                str(normalized.get("source") or "custom"),
                str(normalized.get("mode") or "rule"),
                json_dumps(normalized.get("match") or {}),
                json_dumps(normalized.get("action") or {}),
                now,
                now,
            ),
            commit=True,
        )
        return self.get_monitor(monitor_id)

    def delete_monitor(self, monitor_id: str):
        existing = self.get_monitor(monitor_id)
        if existing and existing.get("source") == "builtin":
            raise ValueError("Builtin monitors are read-only")
        self._execute("DELETE FROM monitors WHERE id = ?", (str(monitor_id),), commit=True)
        return True

    def set_monitor_enabled(self, monitor_id: str, enabled: bool):
        """Flip a monitor's `enabled` flag only - unlike `save_monitor`,
        this is allowed for builtin monitors too. Builtins stay read-only
        for their definition (name/match/action can't be edited, and they
        can't be deleted), but toggling one off is just "stop applying this
        rule", not a change to what the rule does."""
        existing = self.get_monitor(monitor_id)
        if not existing:
            raise ValueError(f"Unknown monitor id: {monitor_id}")
        now = utc_now()
        self._execute(
            "UPDATE monitors SET enabled = ?, updated_at = ? WHERE id = ?",
            (1 if enabled else 0, now, str(monitor_id)),
            commit=True,
        )
        return self.get_monitor(monitor_id)

    def get_monitor_filter_enabled(self) -> bool:
        default = "1" if MONITOR_FILTER_DEFAULT else "0"
        value = self.get_runtime_config("monitor_filter_enabled", default)
        return str(value).strip().lower() in {"1", "true", "yes", "on"}

    def set_monitor_filter_enabled(self, value: bool):
        self.set_runtime_config("monitor_filter_enabled", "1" if value else "0")
        return self.get_monitor_filter_enabled()

    def list_count(self, table: str) -> int:
        row = self._fetchone(f"SELECT COUNT(*) AS count FROM {table}")
        return int(row["count"] or 0) if row else 0

    def list_payload_sizes(self):
        return self._fetchall(
            """
            SELECT
              CASE
                WHEN response_size < 128 THEN 'tiny'
                WHEN response_size < 512 THEN 'small'
                WHEN response_size < 2048 THEN 'medium'
                ELSE 'large'
              END AS bucket,
              COUNT(*) AS value
            FROM payloads
            GROUP BY bucket
            ORDER BY value DESC, bucket ASC
            """
        )

    def top_protocols(self, *, limit=8):
        return self._fetchall(
            """
            SELECT proto AS label, COUNT(*) AS value
            FROM packets
            GROUP BY proto
            ORDER BY value DESC, label ASC
            LIMIT ?
            """,
            (int(limit),),
        )

    def top_ports(self, *, limit=10):
        return self._fetchall(
            """
            SELECT
              COALESCE(NULLIF(dst_port, 0), src_port) AS port,
              COUNT(*) AS value
            FROM packets
            WHERE COALESCE(NULLIF(dst_port, 0), src_port) > 0
            GROUP BY port
            ORDER BY value DESC, port ASC
            LIMIT ?
            """,
            (int(limit),),
        )

    def top_ips(self, *, limit=10):
        return self._fetchall(
            """
            SELECT ip, COUNT(*) AS value
            FROM (
              SELECT src_ip AS ip FROM packets WHERE src_ip != ''
              UNION ALL
              SELECT dst_ip AS ip FROM packets WHERE dst_ip != ''
            )
            GROUP BY ip
            ORDER BY value DESC, ip ASC
            LIMIT ?
            """,
            (int(limit),),
        )

    def top_tag_keys(self, *, limit=10):
        return self._fetchall(
            """
            SELECT key AS label, COUNT(*) AS value
            FROM tags
            GROUP BY key
            ORDER BY value DESC, label ASC
            LIMIT ?
            """,
            (int(limit),),
        )

    def top_service_signatures(self, *, limit=10):
        return self._fetchall(
            """
            SELECT
              COALESCE(NULLIF(banner_text, ''), summary, payload_text, 'payload') AS label,
              COUNT(*) AS value
            FROM packets
            WHERE COALESCE(NULLIF(banner_text, ''), summary, payload_text, '') != ''
            GROUP BY label
            ORDER BY value DESC, label ASC
            LIMIT ?
            """,
            (int(limit),),
        )

    def summary_counts(self) -> dict:
        sessions = self.list_count("sessions")
        packets = self.list_count("packets")
        payloads = self.list_count("payloads")
        tags = self.list_count("tags")
        flows = self.list_count("flows")
        rules = self.list_count("rulesets")
        unique_hosts_row = self._fetchone(
            """
            SELECT COUNT(DISTINCT ip) AS count
            FROM (
                SELECT src_ip AS ip FROM packets WHERE src_ip != ''
                UNION ALL
                SELECT dst_ip AS ip FROM packets WHERE dst_ip != ''
            )
            """
        )
        return {
            "sessions": sessions,
            "packets": packets,
            "payloads": payloads,
            "tags": tags,
            "flows": flows,
            "rulesets": rules,
            "open_packets": self._count_where("packets", "state = 'open'"),
            "filtered_packets": self._count_where("packets", "state = 'filtered'"),
            "unique_hosts": int(unique_hosts_row["count"] or 0) if unique_hosts_row else 0,
        }

    def _count_where(self, table_or_subquery: str, where_clause: str, *, count_distinct=False, distinct_column="id"):
        if count_distinct:
            sql = f"SELECT COUNT(DISTINCT {distinct_column}) AS count FROM {table_or_subquery} WHERE {where_clause}"
        else:
            sql = f"SELECT COUNT(*) AS count FROM {table_or_subquery} WHERE {where_clause}"
        row = self._fetchone(sql)
        return int(row["count"] or 0) if row else 0

    def dashboard_snapshot(self, *, ws_clients=None) -> dict:
        ws_clients = list(ws_clients or [])
        sessions = self.list_sessions(limit=20)
        packets = self.list_packets(limit=20)
        payloads = self.list_payloads(limit=20)
        protocols = self.list_protocols()
        ports_by_proto = {}
        for proto in protocols:
            ports_by_proto[proto] = self.list_packets(proto=proto, limit=12)
        counts = {
            "count_targets": self.list_count("sessions"),
            "count_ports": self.list_count("packets"),
            "count_banners": self.list_count("payloads"),
            "count_tags": self.list_count("tags"),
            "count_rulesets": self.list_count("rulesets"),
            "count_monitors": self.list_count("monitors"),
            "count_domains": self.list_count("domains"),
            "count_paths": self.list_count("paths"),
        }
        return {
            "generated_at": utc_now(),
            "counts": counts,
            "sessions": sessions,
            "targets": sessions,
            "packets": packets,
            "ports": ports_by_proto,
            "banners": payloads,
            "tags": self.list_tags(limit=20),
            "ws_clients": ws_clients,
            "protocols": protocols,
        }

    def analytics_snapshot(self) -> dict:
        summary = self.summary_counts()
        packets = self.list_packets(limit=1000)
        sessions = self.list_sessions(limit=1000)
        flows = self.list_flows(limit=1000)
        packets_by_proto = Counter(normalize_protocol_name(row.get("proto")) for row in packets)
        states_by_proto = defaultdict(Counter)
        for row in packets:
            proto = normalize_protocol_name(row.get("proto"))
            state = str(row.get("state") or "open").strip().lower()
            states_by_proto[proto][state] += 1
        ports_by_proto = [
            {"label": proto, "value": count}
            for proto, count in packets_by_proto.most_common()
            if proto
        ]
        ports_state_by_proto = []
        for proto, counter in states_by_proto.items():
            rows = [{"label": state, "value": value} for state, value in counter.most_common()]
            ports_state_by_proto.append({"label": proto, "series": rows})
        top_open_ports = self.top_ports(limit=12)
        top_ips_by_open_ports = self.top_ips(limit=12)
        risk_ports = [
            item for item in top_open_ports if safe_int(item.get("port"), 0) in {21, 22, 23, 25, 53, 110, 135, 139, 143, 445, 3389}
        ]
        targets_by_status = [
            {"label": label, "value": value}
            for label, value in Counter(str(row.get("status") or "stopped").strip().lower() for row in sessions).most_common()
        ]
        target_progress_buckets = self._bucket_rows([safe_float(row.get("progress", 0.0), 0.0) for row in sessions])
        banner_length_buckets = self._bucket_rows([safe_int(row.get("response_size", 0), 0) for row in self.list_payloads(limit=1000)], size_mode=True)
        top_tag_keys = self.top_tag_keys(limit=12)
        top_service_signatures = self.top_service_signatures(limit=12)
        timeline = self._timeline_snapshot(packets, sessions, flows)
        return {
            "generated_at": utc_now(),
            "summary": {
                "targets": summary["sessions"],
                "ports": summary["packets"],
                "open_ports": summary["open_packets"],
                "filtered_ports": summary["filtered_packets"],
                "banners": summary["payloads"],
                "tags": summary["tags"],
                "favicons": 0,
                "unique_hosts": summary["unique_hosts"],
            },
            "ports_by_proto": ports_by_proto,
            "ports_state_by_proto": ports_state_by_proto,
            "top_open_ports": top_open_ports,
            "top_ips_by_open_ports": top_ips_by_open_ports,
            "risk_ports": risk_ports,
            "targets_by_status": targets_by_status,
            "target_progress_buckets": target_progress_buckets,
            "banner_length_buckets": banner_length_buckets,
            "top_tag_keys": top_tag_keys,
            "top_service_signatures": top_service_signatures,
            "timeline": timeline,
        }

    def soc_analysis_snapshot(self, *, cycles=4, limit=PACKET_TABLE_LIMIT) -> dict:
        cycle_count = clamp_int(cycles, 1, 4)
        sample_limit = clamp_int(limit, 250, PACKET_TABLE_LIMIT)
        packets = self.list_packets(limit=sample_limit)
        payloads = self.list_payloads(limit=min(sample_limit, PAYLOAD_TABLE_LIMIT))
        tags = self.list_tags(limit=min(sample_limit * 2, TAG_TABLE_LIMIT))
        flows = self.list_flows(limit=min(sample_limit, FLOW_TABLE_LIMIT))
        snapshot = self.analytics_snapshot()
        snapshot["timeline"] = self._timeline_snapshot(packets, self.list_sessions(limit=1000), flows)

        risky_ports = {21, 22, 23, 25, 53, 110, 135, 139, 143, 445, 3389}
        packet_total = len(packets)
        direction_counts = Counter(
            str(row.get("direction") or "unknown").strip().lower() or "unknown"
            for row in packets
        )
        state_counts = Counter(
            str(row.get("state") or "open").strip().lower() or "open"
            for row in packets
        )
        proto_counts = Counter(normalize_protocol_name(row.get("proto")) for row in packets)
        row_scope_counts = Counter()
        host_counts = Counter()
        host_protocols = defaultdict(Counter)
        host_ports = defaultdict(Counter)
        host_scopes: dict[str, str] = {}
        port_counts = Counter()
        port_protocols = defaultdict(Counter)
        port_scopes = defaultdict(Counter)
        conversation_counts = Counter()
        payload_signatures = Counter()
        payload_signature_examples = defaultdict(list)
        tag_key_counts = Counter()
        tag_value_counts = Counter()
        public_hosts = set()
        private_hosts = set()
        local_hosts = set()

        for row in packets:
            proto = normalize_protocol_name(row.get("proto"))
            src_ip = str(row.get("src_ip") or "").strip()
            dst_ip = str(row.get("dst_ip") or "").strip()
            src_port = safe_int(row.get("src_port"), 0)
            dst_port = safe_int(row.get("dst_port"), 0)
            unique_hosts = {host for host in (src_ip, dst_ip) if host}
            unique_ports = {port for port in (src_port, dst_port) if port > 0}
            scopes = {_soc_ip_scope(host) for host in unique_hosts}
            scopes.discard("unknown")
            if scopes == {"local"}:
                row_scope = "local"
            elif "public" in scopes and "private" in scopes:
                row_scope = "cross-scope"
            elif "public" in scopes:
                row_scope = "public"
            elif "private" in scopes:
                row_scope = "private"
            elif "local" in scopes:
                row_scope = "local"
            else:
                row_scope = "unknown"
            row_scope_counts[row_scope] += 1

            for host in unique_hosts:
                host_counts[host] += 1
                host_protocols[host][proto] += 1
                for port in unique_ports:
                    host_ports[host][port] += 1
                if host not in host_scopes:
                    host_scopes[host] = _soc_ip_scope(host)
                scope = host_scopes[host]
                if scope == "public":
                    public_hosts.add(host)
                elif scope == "private":
                    private_hosts.add(host)
                elif scope == "local":
                    local_hosts.add(host)

            for port in unique_ports:
                port_counts[port] += 1
                port_protocols[port][proto] += 1
                port_scopes[port][row_scope] += 1

            if src_ip and dst_ip:
                port_label = "/".join(str(port) for port in sorted(unique_ports)) if unique_ports else "0"
                conversation_counts[(src_ip, dst_ip, proto, port_label, row_scope)] += 1

        for payload in payloads:
            signature = _soc_payload_signature(payload.get("response_plain") or payload.get("summary"))
            payload_signatures[signature] += 1
            example = normalize_text(payload.get("response_plain") or payload.get("summary") or "", limit=120)
            if example and len(payload_signature_examples[signature]) < 3:
                payload_signature_examples[signature].append(example)

        for tag in tags:
            key = str(tag.get("key") or "").strip()
            value = str(tag.get("value") or "").strip()
            if key:
                tag_key_counts[key] += 1
            if value:
                tag_value_counts[value] += 1

        findings = []
        cycles_data = []
        finding_seq = 0

        def add_finding(cycle_id, severity, category, title, evidence, recommendation, confidence=0.8):
            nonlocal finding_seq
            finding_seq += 1
            finding = {
                "id": f"soc-{finding_seq}",
                "cycle": cycle_id,
                "severity": severity,
                "category": category,
                "title": title,
                "confidence": round(float(confidence), 2),
                "evidence": [str(item) for item in evidence if str(item).strip()],
                "recommendation": str(recommendation or "").strip(),
            }
            findings.append(finding)
            return finding["id"]

        def host_note(host, count):
            scope = host_scopes.get(host, _soc_ip_scope(host))
            notes = []
            if host == "127.0.0.1":
                notes.append("loopback")
            if scope == "public":
                notes.append("validate ownership")
            elif scope == "private":
                notes.append("internal")
            elif scope == "local":
                notes.append("local")
            if count >= max(10, packet_total // 2):
                notes.append("dominant")
            if any(port in risky_ports for port in host_ports.get(host, {})):
                notes.append("sensitive port")
            return ", ".join(notes) if notes else "observed"

        def conversation_note(src, dst, proto, port_label, row_scope):
            notes = []
            if src == dst == "127.0.0.1":
                notes.append("loopback")
            if row_scope == "cross-scope":
                notes.append("public->private")
            elif row_scope in {"public", "private", "local"}:
                notes.append(row_scope)
            if port_label == "51820" or "51820" in port_label:
                notes.append("tunnel-like")
            if port_label == "443" or "443" in port_label:
                notes.append("tls/web")
            if proto == "udp":
                notes.append("udp")
            return ", ".join(notes) if notes else "observed"

        def port_note(port, row_scope):
            notes = []
            if port in risky_ports:
                notes.append("sensitive port")
            if port >= 49152 and row_scope == "local":
                notes.append("ephemeral")
            if row_scope == "cross-scope":
                notes.append("cross-scope")
            elif row_scope in {"public", "private", "local"}:
                notes.append(row_scope)
            if port == 443:
                notes.append("tls/web")
            if port == 51820:
                notes.append("tunnel-like")
            return ", ".join(notes) if notes else "observed"

        def payload_note(signature):
            return {
                "structured": "JSON-like telemetry",
                "http-like": "cleartext HTTP",
                "noisy": "low semantic density",
                "text": "plain text",
                "empty": "empty payloads",
            }.get(signature, "observed")

        top_protocol_rows = [
            {"label": proto, "value": value}
            for proto, value in proto_counts.most_common()
            if proto
        ]
        top_public_hosts = [
            host for host, _ in host_counts.most_common()
            if host_scopes.get(host) == "public"
        ]
        top_host_rows = []
        for host, count in host_counts.most_common(8):
            protocols = ", ".join(proto for proto, _ in host_protocols[host].most_common(3)) or "unknown"
            ports = ", ".join(str(port) for port, _ in host_ports[host].most_common(3)) or "-"
            top_host_rows.append(
                {
                    "ip": host,
                    "value": count,
                    "scope": host_scopes.get(host, _soc_ip_scope(host)),
                    "protocols": protocols,
                    "ports": ports,
                    "note": host_note(host, count),
                }
            )

        top_conversation_rows = []
        for (src_ip, dst_ip, proto, port_label, row_scope), count in conversation_counts.most_common(8):
            top_conversation_rows.append(
                {
                    "label": f"{src_ip} -> {dst_ip}",
                    "value": count,
                    "proto": proto,
                    "ports": port_label,
                    "scope": row_scope,
                    "note": conversation_note(src_ip, dst_ip, proto, port_label, row_scope),
                }
            )

        top_port_rows = []
        for port, count in port_counts.most_common(8):
            protocols = ", ".join(proto for proto, _ in port_protocols[port].most_common(3)) or "unknown"
            scope = port_scopes[port].most_common(1)[0][0] if port_scopes[port] else "unknown"
            top_port_rows.append(
                {
                    "port": port,
                    "value": count,
                    "protocols": protocols,
                    "scope": scope,
                    "note": port_note(port, scope),
                }
            )

        payload_pattern_rows = []
        for signature, count in payload_signatures.most_common():
            examples = payload_signature_examples.get(signature, [])
            payload_pattern_rows.append(
                {
                    "label": signature,
                    "value": count,
                    "note": payload_note(signature),
                    "example": examples[0] if examples else "",
                }
            )

        total_local_rows = row_scope_counts["local"]
        total_cross_scope_rows = row_scope_counts["cross-scope"]
        total_public_rows = row_scope_counts["public"]
        total_private_rows = row_scope_counts["private"]
        total_unknown_rows = row_scope_counts["unknown"]
        direction_unknown_rows = direction_counts["unknown"]
        direction_unknown_ratio = (direction_unknown_rows / packet_total) if packet_total else 0.0
        noisy_payloads = payload_signatures["noisy"]
        structured_payloads = payload_signatures["structured"]

        cycle_1_findings = []
        cycle_1_observations = []
        if top_protocol_rows:
            cycle_1_observations.append(
                ", ".join(f"{item['label']}={item['value']}" for item in top_protocol_rows[:3])
            )
        if packet_total:
            cycle_1_observations.append(f"{total_local_rows} local rows out of {packet_total} sampled packets")
            cycle_1_observations.append(f"{total_cross_scope_rows} cross-scope rows detected")
        if packet_total and total_local_rows >= int(packet_total * 0.5):
            cycle_1_findings.append(
                add_finding(
                    1,
                    "info",
                    "baseline",
                    f"Loopback and local traffic dominate ({total_local_rows}/{packet_total})",
                    [
                        f"local rows={total_local_rows}",
                        f"private rows={total_private_rows}",
                        f"public rows={total_public_rows}",
                    ],
                    "Treat most of this sample as local telemetry and move the hunt to the outliers.",
                    confidence=0.97,
                )
            )
        if packet_total and direction_unknown_ratio >= 0.5:
            cycle_1_findings.append(
                add_finding(
                    1,
                    "low",
                    "telemetry-gap",
                    f"Direction is unknown on {direction_unknown_rows}/{packet_total} rows",
                    [
                        f"unknown direction rows={direction_unknown_rows}",
                        "source/destination pairing is more reliable than direction metadata here",
                    ],
                    "Use IP pairing and port ownership until the capture pipeline emits better direction labels.",
                    confidence=0.99,
                )
            )
        if top_public_hosts:
            public_preview = ", ".join(top_public_hosts[:2])
            cycle_1_findings.append(
                add_finding(
                    1,
                    "medium",
                    "external-exposure",
                    f"Public hosts are present: {public_preview}",
                    [f"public hosts={len(top_public_hosts)}", public_preview],
                    "Validate ownership and allowed services for the public endpoints before treating them as benign.",
                    confidence=0.85,
                )
            )
        if len([item for item in top_protocol_rows if item["label"]]) <= 2:
            cycle_1_findings.append(
                add_finding(
                    1,
                    "info",
                    "protocol-mix",
                    "The sampled traffic is limited to a narrow protocol mix",
                    [", ".join(item["label"] for item in top_protocol_rows[:3]) or "no protocol data"],
                    "No packet-level evidence of additional protocol families in this slice.",
                    confidence=0.88,
                )
            )
        if not direction_counts.get("unknown") and total_unknown_rows == 0:
            cycle_1_findings.append(
                add_finding(
                    1,
                    "info",
                    "coverage",
                    "No unknown protocol rows or honeypot artifacts are present in this sample",
                    ["unknown protocol rows=0", "honeypot rows=0"],
                    "Keep this slice in the low-risk bucket unless new protocol families appear.",
                    confidence=0.9,
                )
            )
        cycles_data.append(
            {
                "id": 1,
                "title": "Baseline triage",
                "need": [
                    "packet volume",
                    "protocol mix",
                    "local vs public split",
                    "direction metadata",
                ],
                "observations": cycle_1_observations,
                "finding_ids": cycle_1_findings,
                "finding_count": len(cycle_1_findings),
            }
        )

        cycle_2_findings = []
        cycle_2_observations = []
        if top_conversation_rows:
            cycle_2_observations.append(
                f"Top conversation: {top_conversation_rows[0]['label']} ({top_conversation_rows[0]['value']})"
            )
        if top_port_rows:
            cycle_2_observations.append(
                ", ".join(f"{item['port']}={item['value']}" for item in top_port_rows[:4])
            )
        if top_host_rows:
            cycle_2_observations.append(
                f"Top host: {top_host_rows[0]['ip']} ({top_host_rows[0]['value']})"
            )
        if total_local_rows and top_host_rows and top_host_rows[0]["ip"] == "127.0.0.1":
            cycle_2_findings.append(
                add_finding(
                    2,
                    "info",
                    "loopback-hotspot",
                    "Loopback conversations dominate the top of the table",
                    [
                        f"host={top_host_rows[0]['ip']}",
                        f"packets={top_host_rows[0]['value']}",
                        f"ports={top_host_rows[0]['ports']}",
                    ],
                    "Keep this bucket low priority unless the process owner changes.",
                    confidence=0.96,
                )
            )
        if any(safe_int(item.get("port"), 0) == 51820 for item in top_port_rows):
            cycle_2_findings.append(
                add_finding(
                    2,
                    "medium",
                    "tunnel-review",
                    "UDP/51820 is active in the sample",
                    [
                        "port=51820",
                        ", ".join(
                            row["label"]
                            for row in top_conversation_rows
                            if "51820" in str(row.get("ports") or "")
                        )
                        or "no direct conversation note",
                    ],
                    "Validate whether an encrypted tunnel, VPN client, or other remote access path is expected.",
                    confidence=0.9,
                )
            )
        if any(safe_int(item.get("port"), 0) == 443 for item in top_port_rows):
            cycle_2_findings.append(
                add_finding(
                    2,
                    "medium",
                    "tls-review",
                    "Port 443 is present across multiple hosts",
                    [
                        ", ".join(
                            row["label"]
                            for row in top_conversation_rows
                            if "443" in str(row.get("ports") or "")
                        )
                        or "443 conversations present",
                        ", ".join(
                            row["ip"]
                            for row in top_host_rows
                            if row.get("scope") == "public"
                        )
                        or "no public host list",
                    ],
                    "Confirm certificate ownership and whether these TLS-like flows are part of the expected workload.",
                    confidence=0.84,
                )
            )
        if any(item["scope"] == "cross-scope" for item in top_conversation_rows):
            cycle_2_findings.append(
                add_finding(
                    2,
                    "low",
                    "cross-scope",
                    "Cross-scope conversations are visible in the top flows",
                    [
                        ", ".join(item["label"] for item in top_conversation_rows if item["scope"] == "cross-scope")
                        or "no cross-scope rows",
                    ],
                    "Validate whether these public-to-private exchanges are expected and authorized.",
                    confidence=0.8,
                )
            )
        cycles_data.append(
            {
                "id": 2,
                "title": "Conversation drill-down",
                "need": [
                    "top conversations",
                    "hot ports",
                    "peer scopes",
                    "likely service owners",
                ],
                "observations": cycle_2_observations,
                "finding_ids": cycle_2_findings,
                "finding_count": len(cycle_2_findings),
            }
        )

        cycle_3_findings = []
        cycle_3_observations = []
        if payload_pattern_rows:
            cycle_3_observations.append(
                ", ".join(
                    f"{item['label']}={item['value']}"
                    for item in payload_pattern_rows[:4]
                )
            )
        if tag_key_counts:
            cycle_3_observations.append(
                ", ".join(
                    f"{label}={value}"
                    for label, value in tag_key_counts.most_common(4)
                )
            )
        if structured_payloads and noisy_payloads:
            cycle_3_findings.append(
                add_finding(
                    3,
                    "info",
                    "payload-shape",
                    "The sample splits between structured and noisy payloads",
                    [
                        f"structured payloads={structured_payloads}",
                        f"noisy payloads={noisy_payloads}",
                    ],
                    "Use payload shape to separate telemetry from opaque transport noise.",
                    confidence=0.86,
                )
            )
        if structured_payloads:
            cycle_3_findings.append(
                add_finding(
                    3,
                    "info",
                    "telemetry",
                    "Structured JSON-like payloads are present in the local traffic",
                    [
                        ", ".join(payload_signature_examples.get("structured", [])[:2]) or "structured payload evidence present",
                    ],
                    "The loopback activity looks like internal telemetry or event relay traffic.",
                    confidence=0.82,
                )
            )
        if noisy_payloads and top_public_hosts:
            cycle_3_findings.append(
                add_finding(
                    3,
                    "low",
                    "opaque-transport",
                    "Noisy payloads appear on the public-facing side of the sample",
                    [
                        f"noisy payloads={noisy_payloads}",
                        ", ".join(top_public_hosts[:2]),
                    ],
                    "Validate the noisy flows only if they are not expected encrypted or compressed transports.",
                    confidence=0.76,
                )
            )
        if tag_key_counts:
            cycle_3_findings.append(
                add_finding(
                    3,
                    "info",
                    "tag-depth",
                    "Tags stay at transport metadata depth",
                    [
                        ", ".join(f"{label}={value}" for label, value in tag_key_counts.most_common(4)),
                        ", ".join(f"{label}={value}" for label, value in tag_value_counts.most_common(4)) or "no tag values",
                    ],
                    "Add application context or host ownership metadata if you want deeper SOC triage.",
                    confidence=0.9,
                )
            )
        cycles_data.append(
            {
                "id": 3,
                "title": "Payload and tag correlation",
                "need": [
                    "payload shape",
                    "tag depth",
                    "application context",
                    "evidence quality",
                ],
                "observations": cycle_3_observations,
                "finding_ids": cycle_3_findings,
                "finding_count": len(cycle_3_findings),
            }
        )

        cycle_4_findings = []
        cycle_4_observations = []
        if top_host_rows:
            cycle_4_observations.append(
                f"Most active host: {top_host_rows[0]['ip']} ({top_host_rows[0]['scope']})"
            )
        if payload_pattern_rows:
            cycle_4_observations.append(
                f"Payload mix: {', '.join(item['label'] for item in payload_pattern_rows[:3])}"
            )

        questions = []
        if top_host_rows:
            questions.append(f"Which process owns {top_host_rows[0]['ip']} and its top ports {top_host_rows[0]['ports']}?")
        if top_public_hosts:
            questions.append(f"Are the public endpoints {', '.join(top_public_hosts[:2])} expected in this environment?")
        if any(item["port"] == 51820 for item in top_port_rows):
            questions.append("Is UDP/51820 expected or should it be treated as a tunnel review item?")
        if direction_unknown_rows:
            questions.append("Can the capture pipeline improve direction tagging for faster triage?")

        if questions:
            cycle_4_observations.append(f"Analyst questions: {len(questions)}")

        selected_cycle_count = cycle_count
        selected_cycle_ids = set(range(1, selected_cycle_count + 1))
        selected_findings = [finding for finding in findings if finding["cycle"] in selected_cycle_ids]
        if selected_findings:
            severity_weights = {"high": 20, "medium": 12, "low": 5, "info": 2}
            risk_score = sum(severity_weights.get(finding["severity"], 1) for finding in selected_findings)
        else:
            risk_score = 0
        risk_score += min(10, len(top_public_hosts) * 4)
        risk_score += min(10, total_cross_scope_rows * 2)
        risk_score += min(8, int(direction_unknown_ratio * 20))
        risk_score += min(8, noisy_payloads * 2)
        if total_local_rows >= packet_total * 0.5:
            risk_score -= 4
        risk_score = clamp_int(risk_score, 0, 100)
        if risk_score >= 65:
            verdict = "investigate"
        elif risk_score >= 35:
            verdict = "review"
        elif risk_score >= 15:
            verdict = "monitor"
        else:
            verdict = "observe"

        if verdict in {"investigate", "review"}:
            cycle_4_findings.append(
                add_finding(
                    4,
                    "medium" if verdict == "review" else "high",
                    "priority",
                    f"SOC priority is {verdict}",
                    [
                        f"risk score={risk_score}",
                        f"public hosts={len(top_public_hosts)}",
                        f"cross-scope rows={total_cross_scope_rows}",
                    ],
                    "Focus on external 443 and 51820 flows first, then map the loopback owners.",
                    confidence=0.9,
                )
            )
        if questions:
            cycle_4_findings.append(
                add_finding(
                    4,
                    "info",
                    "hunt-questions",
                    "Analyst questions are ready for follow-up",
                    questions[:3],
                    "Use the questions as the next pass for host ownership and service validation.",
                    confidence=0.93,
                )
            )
        cycles_data.append(
            {
                "id": 4,
                "title": "Triage decision",
                "need": [
                    "priority",
                    "open questions",
                    "next actions",
                    "validation targets",
                ],
                "observations": cycle_4_observations,
                "finding_ids": cycle_4_findings,
                "finding_count": len(cycle_4_findings),
            }
        )

        selected_cycles = cycles_data[:selected_cycle_count]
        selected_finding_ids = {
            finding_id
            for cycle in selected_cycles
            for finding_id in cycle["finding_ids"]
        }
        selected_findings = [finding for finding in findings if finding["id"] in selected_finding_ids]
        severity_counts = Counter(finding["severity"] for finding in selected_findings)
        if not questions:
            questions = [
                "Which host should be investigated first?",
                "Are the public flows expected?",
                "Is the loopback telemetry an internal control channel?",
            ]

        snapshot["soc_summary"] = {
            "sampled_packets": packet_total,
            "sampled_payloads": len(payloads),
            "sampled_tags": len(tags),
            "sampled_flows": len(flows),
            "protocols_seen": len([proto for proto in proto_counts if proto]),
            "local_rows": total_local_rows,
            "private_rows": total_private_rows,
            "public_rows": total_public_rows,
            "cross_scope_rows": total_cross_scope_rows,
            "unknown_rows": total_unknown_rows,
            "direction_unknown_rows": direction_unknown_rows,
            "structured_payloads": structured_payloads,
            "noisy_payloads": noisy_payloads,
            "risk_score": risk_score,
            "verdict": verdict,
            "priority": verdict,
            "findings_total": len(selected_findings),
            "high_findings": severity_counts.get("high", 0),
            "medium_findings": severity_counts.get("medium", 0),
            "low_findings": severity_counts.get("low", 0),
            "info_findings": severity_counts.get("info", 0),
        }
        snapshot["cycles"] = selected_cycles
        snapshot["findings"] = selected_findings
        snapshot["top_hosts"] = top_host_rows
        snapshot["top_conversations"] = top_conversation_rows
        snapshot["top_ports"] = top_port_rows
        snapshot["payload_patterns"] = payload_pattern_rows
        snapshot["questions"] = questions
        snapshot["signals"] = {
            "protocols": top_protocol_rows,
            "directions": [
                {"label": label, "value": value}
                for label, value in direction_counts.most_common()
            ],
            "states": [
                {"label": label, "value": value}
                for label, value in state_counts.most_common()
            ],
            "row_scopes": [
                {"label": label, "value": value}
                for label, value in row_scope_counts.most_common()
            ],
        }
        return snapshot

    def _bucket_rows(self, values, *, size_mode=False):
        buckets = Counter()
        for value in values:
            numeric = safe_float(value, 0.0) if not size_mode else safe_int(value, 0)
            if numeric <= 0:
                bucket = "0"
            elif size_mode:
                if numeric < 128:
                    bucket = "<128B"
                elif numeric < 512:
                    bucket = "128-511B"
                elif numeric < 2048:
                    bucket = "512B-2KB"
                else:
                    bucket = "2KB+"
            else:
                if numeric < 20:
                    bucket = "0-19"
                elif numeric < 40:
                    bucket = "20-39"
                elif numeric < 60:
                    bucket = "40-59"
                elif numeric < 80:
                    bucket = "60-79"
                else:
                    bucket = "80-100"
            buckets[bucket] += 1
        return [{"label": label, "value": value} for label, value in buckets.most_common()]

    def _timeline_snapshot(self, packets, sessions, flows):
        buckets = Counter()
        for row in packets:
            created = str(row.get("created_at") or "")[:10]
            if created:
                buckets[created] += 1
        if not buckets:
            for row in sessions:
                created = str(row.get("created_at") or "")[:10]
                if created:
                    buckets[created] += 1
        if not buckets:
            for row in flows:
                created = str(row.get("created_at") or "")[:10]
                if created:
                    buckets[created] += 1
        return [{"label": label, "value": value} for label, value in sorted(buckets.items())][-30:]

    def map_snapshot(self, limit=500) -> dict:
        packets = self.list_packets(limit=limit)
        hosts = {}
        public_points = []
        private_hosts = []
        seen = set()
        for row in packets:
            for ip_key in ("src_ip", "dst_ip"):
                ip = str(row.get(ip_key) or "").strip()
                if not ip or ip in seen:
                    continue
                seen.add(ip)
                node = self._host_node(ip)
                hosts[ip] = node
                if node["private"]:
                    private_hosts.append(node)
                else:
                    public_points.append(node)
        links = []
        for row in packets:
            src = str(row.get("src_ip") or "").strip()
            dst = str(row.get("dst_ip") or "").strip()
            if not src or not dst:
                continue
            links.append(
                {
                    "source": src,
                    "target": dst,
                    "proto": row.get("proto"),
                    "value": max(1, safe_int(row.get("length", 0), 0)),
                }
            )
        summary = {
            "total_hosts": len(hosts),
            "public_hosts": len([item for item in hosts.values() if not item["private"]]),
            "private_hosts": len([item for item in hosts.values() if item["private"]]),
            "unmapped_public_hosts": len(
                [
                    item
                    for item in hosts.values()
                    if not item["private"] and (item.get("lat") is None or item.get("lon") is None)
                ]
            ),
            "total_ports": self.list_count("packets"),
            "total_open_ports": self._count_where("packets", "state = 'open'"),
        }
        resolved_public_hosts = len(
            [
                item
                for item in public_points
                if item.get("lat") is not None and item.get("lon") is not None
            ]
        )
        geoip_source = self._geoip_resolver.describe_source()
        return {
            "generated_at": utc_now(),
            "origin": {"ip": "127.0.0.1", "label": "Sniff origin"},
            "summary": summary,
            "public_points": public_points,
            "private_hosts": private_hosts,
            "private_bucket": {"count": len(private_hosts)},
            "geoip": {
                "source": geoip_source,
                "rows": resolved_public_hosts,
                "resolved_public_hosts": resolved_public_hosts,
                "total_public_hosts": len(public_points),
                "generated_at": utc_now(),
                "partial": resolved_public_hosts < len(public_points),
                "precision": "country" if geoip_source.startswith("country-db") else "",
            },
            "links": links,
        }

    def _host_node(self, ip: str) -> dict:
        scope = _ip_scope(ip)
        private = scope != "public"
        geo = self._geoip_resolver.lookup(ip) if not private else {}
        return {
            "id": ip,
            "ip": ip,
            "label": ip,
            "private": private,
            "scope": scope,
            "lat": safe_float(geo.get("lat"), None) if geo.get("lat") is not None else None,
            "lon": safe_float(geo.get("lon"), None) if geo.get("lon") is not None else None,
            "country_code": str(geo.get("country_code") or "").upper(),
            "country": str(geo.get("country") or "").strip(),
            "geo_precision": str(geo.get("precision") or "").strip(),
        }

    def endpoint_catalog(self, routes: list[dict]) -> list[dict]:
        return [
            {
                "method": str(route.get("method") or "GET"),
                "path": str(route.get("path") or "/"),
                "desc": str(route.get("desc") or ""),
            }
            for route in routes
        ]

    def ip_intel(self, ip: str) -> dict:
        ip = str(ip or "").strip()
        if not ip:
            raise ValueError("ip is required")
        related_packets = self.list_packets(search=ip, limit=250)
        related_flows = self.list_flows(search=ip, limit=100)
        related_payloads = [
            payload for payload in self.list_payloads(limit=250)
            if payload.get("ip") == ip or ip in str(payload.get("flow_key") or "")
        ]
        related_tags = [
            tag for tag in self.list_tags(limit=400)
            if tag.get("ip") == ip or ip in str(tag.get("flow_key") or "")
        ]
        services = []
        for row in related_packets:
            tags = json_loads(row.get("tags_json"), default=[]) or []
            tags_text = ", ".join(
                str(tag.get("value") or tag.get("key") or "").strip()
                for tag in tags
                if isinstance(tag, dict) and (tag.get("value") or tag.get("key"))
            )
            if not tags_text:
                tags_text = ", ".join(
                    str(tag).strip()
                    for tag in tags
                    if str(tag).strip()
                )
            services.append(
                {
                    "ip": row.get("dst_ip") or row.get("src_ip") or ip,
                    "port": safe_int(row.get("dst_port") or row.get("src_port"), 0),
                    "proto": row.get("proto") or "unknown",
                    "state": row.get("state") or "open",
                    "banner": row.get("banner_text") or row.get("summary") or "",
                    "tags_text": tags_text,
                }
            )
        transport = {
            "services": unique_ordered_dicts(services, key_fields=("ip", "port", "proto")),
            "banners": related_payloads,
            "tags": related_tags,
            "flows": related_flows,
        }
        firewall = {
            "summary": "Observed",
            "status": "mixed_filtering" if related_packets else "low_filtering",
        }
        host_node = self._host_node(ip)
        geo = {
            "found": bool(host_node.get("country_code")),
            "area": host_node.get("country") or "",
            "country": host_node.get("country") or "",
            "country_code": host_node.get("country_code") or "",
            "lat": host_node.get("lat"),
            "lon": host_node.get("lon"),
            "precision": host_node.get("geo_precision") or "",
        }
        return {
            "ip": ip,
            "summary": {
                "packets": len(related_packets),
                "flows": len(related_flows),
                "payloads": len(related_payloads),
                "tags": len(related_tags),
            },
            "host": {
                "transport": transport,
                "firewall": firewall,
                "geo": geo,
            },
            "domains": [],
            "ttl_path": [],
            "intel": {
                "services": transport["services"],
                "payloads": related_payloads,
                "tags": related_tags,
            },
        }

    def register_packet(self, packet: dict) -> dict:
        now = utc_now()
        rule_hits = packet.get("rule_hits") if isinstance(packet.get("rule_hits"), list) else []
        tags = packet.get("tags") if isinstance(packet.get("tags"), list) else []
        payload_text = normalize_text(packet.get("payload_text") or "", limit=PAYLOAD_TEXT_MAX_CHARS)
        summary_text = normalize_text(packet.get("summary") or "", limit=PAYLOAD_TEXT_MAX_CHARS)
        banner_text = normalize_text(packet.get("banner_text") or payload_text, limit=PAYLOAD_TEXT_MAX_CHARS)
        payload_hex = str(packet.get("payload_hex") or "")
        length = safe_int(packet.get("length", 0), 0)
        payload_len = safe_int(packet.get("payload_len", 0), 0)
        state = str(packet.get("state") or ("open" if payload_len else "filtered")).strip().lower() or "open"
        scan_state = str(packet.get("scan_state") or "active").strip().lower() or "active"
        flow_key = str(packet.get("flow_key") or stable_flow_key(
            packet.get("proto", "unknown"),
            packet.get("src_ip", ""),
            packet.get("src_port", 0),
            packet.get("dst_ip", ""),
            packet.get("dst_port", 0),
        )).strip()
        packet_row = (
            flow_key,
            str(packet.get("interface") or "").strip(),
            str(packet.get("direction") or "unknown").strip(),
            str(packet.get("eth_src") or "").strip(),
            str(packet.get("eth_dst") or "").strip(),
            safe_int(packet.get("eth_type", 0), 0),
            safe_int(packet.get("ip_version", 0), 0),
            str(packet.get("src_ip") or "").strip(),
            str(packet.get("dst_ip") or "").strip(),
            normalize_protocol_name(packet.get("proto")),
            safe_int(packet.get("src_port", 0), 0),
            safe_int(packet.get("dst_port", 0), 0),
            safe_int(packet.get("ttl", 0), 0),
            safe_int(packet.get("hop_limit", 0), 0),
            length,
            payload_len,
            state,
            scan_state,
            str(packet.get("tcp_flags") or "").strip(),
            safe_int(packet.get("icmp_type", 0), 0),
            safe_int(packet.get("icmp_code", 0), 0),
            safe_int(packet.get("arp_opcode", 0), 0),
            summary_text,
            payload_text,
            payload_hex,
            banner_text,
            str(packet.get("domain") or "").strip().lower(),
            str(packet.get("domain_source") or "").strip(),
            str(packet.get("http_method") or "").strip().upper(),
            str(packet.get("http_path") or "").strip(),
            str(packet.get("http_host") or "").strip().lower(),
            json_dumps(tags),
            json_dumps(rule_hits),
            packet.get("raw_packet"),
            now,
            now,
        )
        with self._lock:
            session_id = self._ensure_session(safe_int(packet.get("session_id", 0), 0))
            cursor = self._conn.execute(
                """
                INSERT INTO packets
                (session_id, flow_key, interface, direction, eth_src, eth_dst, eth_type, ip_version,
                 src_ip, dst_ip, proto, src_port, dst_port, ttl, hop_limit, length, payload_len,
                 state, scan_state, tcp_flags, icmp_type, icmp_code, arp_opcode, summary,
                 payload_text, payload_hex, banner_text, domain, domain_source, http_method,
                 http_path, http_host, tags_json, rule_hits_json, raw_packet,
                 created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (session_id, *packet_row),
            )
            packet_id = cursor.lastrowid
            self._upsert_flow(packet_id, session_id, flow_key, packet, tags, banner_text, now)
            self._insert_tag_rows(packet_id, flow_key, packet, tags, now)
            self._insert_payload_row(packet_id, flow_key, packet, banner_text, now)
            self.bump_session_counters(session_id, length or payload_len, len(rule_hits))
            self._conn.commit()

        return self.get_packet(packet_id)

    def _upsert_flow(self, packet_id: int, session_id: int, flow_key: str, packet: dict, tags: list, banner_text: str, now: str):
        values = (
            flow_key,
            normalize_protocol_name(packet.get("proto")),
            str(packet.get("src_ip") or "").strip(),
            str(packet.get("dst_ip") or "").strip(),
            safe_int(packet.get("src_port", 0), 0),
            safe_int(packet.get("dst_port", 0), 0),
            safe_int(packet.get("length", 0), 0),
            str(packet.get("state") or "open").strip().lower() or "open",
            str(packet.get("scan_state") or "active").strip().lower() or "active",
            banner_text,
            json_dumps([tag.get("key") for tag in tags if isinstance(tag, dict)]),
            now,
            now,
            now,
            now,
        )
        self._conn.execute(
            """
            INSERT INTO flows
            (flow_key, proto, src_ip, dst_ip, src_port, dst_port, packet_count, byte_count,
             state, scan_state, banner_text, tags_json, first_seen, last_seen, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(flow_key) DO UPDATE SET
              packet_count = packet_count + 1,
              byte_count = byte_count + excluded.byte_count,
              state = excluded.state,
              scan_state = excluded.scan_state,
              banner_text = CASE
                WHEN excluded.banner_text != '' THEN excluded.banner_text
                ELSE banner_text
              END,
              tags_json = excluded.tags_json,
              last_seen = excluded.last_seen,
              updated_at = excluded.updated_at
            """,
            values,
        )

    def _insert_tag_rows(self, packet_id: int, flow_key: str, packet: dict, tags: list, now: str):
        if not tags:
            return
        for tag in tags:
            if not isinstance(tag, dict):
                continue
            key = str(tag.get("key") or tag.get("tag") or "").strip()
            value = str(tag.get("value") or tag.get("label") or "").strip()
            if not key:
                continue
            self._conn.execute(
                """
                INSERT INTO tags
                (packet_id, flow_key, ip, port, proto, key, value, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    packet_id,
                    flow_key,
                    str(packet.get("dst_ip") or packet.get("src_ip") or "").strip(),
                    safe_int(packet.get("dst_port") or packet.get("src_port") or 0, 0),
                    normalize_protocol_name(packet.get("proto")),
                    key,
                    value,
                    now,
                    now,
                ),
            )

    def _insert_payload_row(self, packet_id: int, flow_key: str, packet: dict, banner_text: str, now: str):
        payload_text = str(packet.get("payload_text") or "").strip()
        if not payload_text and not banner_text:
            return
        response_plain = banner_text or payload_text
        response_size = len(response_plain.encode("utf-8", errors="ignore"))
        self._conn.execute(
            """
            INSERT INTO payloads
            (packet_id, flow_key, ip, port, proto, response_plain, response_size, scan_state, port_id, favicon_id, state, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                packet_id,
                flow_key,
                str(packet.get("dst_ip") or packet.get("src_ip") or "").strip(),
                safe_int(packet.get("dst_port") or packet.get("src_port") or 0, 0),
                normalize_protocol_name(packet.get("proto")),
                response_plain,
                response_size,
                str(packet.get("scan_state") or "active").strip().lower() or "active",
                packet_id,
                packet_id,
                str(packet.get("state") or "open").strip().lower() or "open",
                now,
                now,
            ),
        )

    def get_packet(self, packet_id: int):
        return self._fetchone("SELECT * FROM packets WHERE id = ?", (packet_id,))

    def get_flow(self, flow_key: str):
        return self._fetchone("SELECT * FROM flows WHERE flow_key = ?", (flow_key,))

    def get_payload(self, payload_id: int):
        return self._fetchone("SELECT * FROM payloads WHERE id = ?", (payload_id,))

    def get_tag(self, tag_id: int):
        return self._fetchone("SELECT * FROM tags WHERE id = ?", (tag_id,))

    def packet_detail_with_tags(self, packet_id: int):
        packet = self.get_packet(packet_id)
        if not packet:
            return None
        packet["tags"] = self._fetchall("SELECT * FROM tags WHERE packet_id = ? ORDER BY id ASC", (packet_id,))
        packet["payload"] = self._fetchone("SELECT * FROM payloads WHERE packet_id = ? ORDER BY id DESC LIMIT 1", (packet_id,))
        return packet

    def trim_oversized_tables(self):
        self._trim_table("packets", PACKET_TABLE_LIMIT)
        self._trim_table("payloads", PAYLOAD_TABLE_LIMIT)
        self._trim_table("flows", FLOW_TABLE_LIMIT)
        self._trim_table("tags", TAG_TABLE_LIMIT)
        self._trim_table("domains", DOMAIN_TABLE_LIMIT)
        self._trim_table("paths", PATH_TABLE_LIMIT)

    def _trim_table(self, table: str, limit: int):
        with self._lock:
            row = self._conn.execute(f"SELECT COUNT(*) AS count FROM {table}").fetchone()
            count = int(row["count"] or 0) if row else 0
            overflow = count - int(limit)
            if overflow <= 0:
                return
            self._conn.execute(
                f"DELETE FROM {table} WHERE id IN (SELECT id FROM {table} ORDER BY id ASC LIMIT ?)",
                (overflow,),
            )
            self._conn.commit()

    def clear_detections(self, scope: str = "all") -> dict:
        """Deletes stored packets/tags/payloads - the underlying data behind
        the Monitors and inbound-service "hits" tables - so an operator can clear
        out noise (e.g. right after tuning/disabling noisy monitors) without
        touching the monitor/listener *definitions* themselves, which live
        in a separate table this never runs a DELETE against.

        Scoped by `packets.interface`: listener traffic is recorded under
        the current "service:" prefix, while older rows may still use the
        legacy "honeypot:" prefix. Everything else is sniffer-side traffic.
        'all' clears both. Never touches `sessions`, `flows`,
        `domains`, or `paths` - those are running counters/catalogs, not
        per-packet detection history, and clearing them out from under an
        active capture session would desync its own live counters.
        """
        scope = str(scope or "all").strip().lower()
        if scope not in {"all", "honeypot", "sniffer"}:
            raise ValueError(f"Unknown scope: {scope!r} (expected 'all', 'honeypot', or 'sniffer')")

        if scope == "all":
            packet_filter = ""
            params: tuple = ()
        elif scope == "honeypot":
            packet_filter = "WHERE interface LIKE ? OR interface = ? OR interface LIKE ? OR interface = ?"
            params = ("honeypot%", "honeypot", "service:%", "service")
        else:
            packet_filter = "WHERE interface NOT LIKE ? AND interface != ? AND interface NOT LIKE ? AND interface != ?"
            params = ("honeypot%", "honeypot", "service:%", "service")

        with self._lock:
            tags_deleted = self._conn.execute(
                f"DELETE FROM tags WHERE packet_id IN (SELECT id FROM packets {packet_filter})", params
            ).rowcount
            payloads_deleted = self._conn.execute(
                f"DELETE FROM payloads WHERE packet_id IN (SELECT id FROM packets {packet_filter})", params
            ).rowcount
            packets_deleted = self._conn.execute(f"DELETE FROM packets {packet_filter}", params).rowcount
            self._conn.commit()

        return {
            "scope": scope,
            "packets": max(0, packets_deleted),
            "tags": max(0, tags_deleted),
            "payloads": max(0, payloads_deleted),
        }

    def read_catalog_file(self, filename: str) -> list[dict]:
        path = resolve_data_file(filename)
        if not path.exists():
            return []
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return []
        if not isinstance(payload, list):
            return []
        return [item for item in payload if isinstance(item, dict)]

    def write_catalog_file(self, filename: str, rows: list[dict]):
        path = resolve_data_file(filename)
        path.write_text(json.dumps(rows, ensure_ascii=False, indent=2), encoding="utf-8")

    def get_runtime_config(self, key: str, default: str = "") -> str:
        row = self._fetchone("SELECT value FROM runtime_config WHERE key = ?", (str(key),))
        if not row:
            return str(default)
        value = row.get("value")
        return str(value if value is not None else default)

    def set_runtime_config(self, key: str, value: str):
        now = utc_now()
        self._execute(
            """
            INSERT INTO runtime_config (key, value, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET
              value = excluded.value,
              updated_at = excluded.updated_at
            """,
            (str(key), str(value), now),
            commit=True,
        )
        return str(value)

    def upsert_catalog_file_row(self, filename: str, row: dict):
        rows = self.read_catalog_file(filename)
        item = dict(row or {})
        item_id = str(item.get("id") or item.get("name") or "").strip()
        if not item_id:
            item_id = f"{filename.rsplit('.', 1)[0]}-{len(rows) + 1}"
            item["id"] = item_id
        found = False
        for index, existing in enumerate(rows):
            existing_id = str(existing.get("id") or existing.get("name") or "").strip()
            if existing_id == item_id:
                rows[index] = item
                found = True
                break
        if not found:
            rows.append(item)
        self.write_catalog_file(filename, rows)
        return item

    def delete_catalog_file_row(self, filename: str, item_id: str):
        rows = self.read_catalog_file(filename)
        filtered = [
            item for item in rows
            if str(item.get("id") or item.get("name") or "").strip() != str(item_id).strip()
        ]
        self.write_catalog_file(filename, filtered)
        return True


def unique_ordered_dicts(rows: list[dict], *, key_fields: tuple[str, ...]):
    seen = set()
    result = []
    for row in rows:
        key = tuple(str(row.get(field) or "").strip() for field in key_fields)
        if key in seen:
            continue
        seen.add(key)
        result.append(row)
    return result
