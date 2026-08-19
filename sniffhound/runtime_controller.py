"""The real `RuntimeController` - owns the active capture engine
(`Sniffer` or `HoneypotEngine`) and switches between them.

Lives in its own module so the privileged capture process
(`capture_service.py`) can use it directly, unchanged, exactly as
`sniffhound.app` used to when everything ran in one process. The web
process talks to this over IPC via `app.RuntimeControllerClient` instead.
"""

from __future__ import annotations

import json
import threading

from .settings import RUNTIME_MODE
from .utils import utc_now


def normalize_runtime_mode(value: str) -> str:
    mode = str(value or "").strip().lower()
    if mode not in {"sniffer", "honeypot"}:
        return "sniffer"
    return mode


def normalize_interface_selection(raw) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        raw_items = [raw]
    elif isinstance(raw, (list, tuple, set)):
        raw_items = list(raw)
    else:
        raw_items = [raw]

    normalized: list[str] = []
    seen: set[str] = set()
    for item in raw_items:
        value = str(item or "").strip()
        if not value or value in seen:
            continue
        normalized.append(value)
        seen.add(value)
    return normalized


def configured_runtime_mode() -> str:
    return normalize_runtime_mode(RUNTIME_MODE)


def read_stored_sniffer_interfaces(store) -> list[str]:
    stored = str(store.get_runtime_config("sniffer_interfaces", "") or "").strip()
    if stored:
        try:
            parsed = json.loads(stored)
        except Exception:
            parsed = [item for item in stored.split(",")]
        normalized = normalize_interface_selection(parsed)
        if normalized or stored in {"[]", ""}:
            return normalized

    legacy = str(store.get_runtime_config("sniffer_interface", "") or "").strip()
    return normalize_interface_selection(legacy)


class RuntimeController:
    def __init__(self, *, store, sniffer, honeypot, hub, capture_auto_start: bool):
        self._store = store
        self._sniffer = sniffer
        self._honeypot = honeypot
        self._hub = hub
        self._capture_auto_start = bool(capture_auto_start)
        self._lock = threading.RLock()
        self.mode = configured_runtime_mode()
        self._store.set_runtime_config("runtime_mode", self.mode)
        try:
            self._sniffer.set_interfaces(read_stored_sniffer_interfaces(self._store))
        except ValueError:
            self._store.set_runtime_config("sniffer_interfaces", "[]")
            self._store.set_runtime_config("sniffer_interface", "")

    def current_engine(self):
        return self._honeypot if self.mode == "honeypot" else self._sniffer

    def snapshot(self):
        active = self.current_engine().snapshot()
        return {
            "mode": self.mode,
            "supported_modes": ["sniffer", "honeypot"],
            "auto_start": bool(self._capture_auto_start),
            "active": active,
            "sniffer": self._sniffer.snapshot(),
            "honeypot": self._honeypot.snapshot(),
        }

    def _broadcast_snapshot(self, snapshot: dict):
        self._hub.broadcast(
            {
                "type": "runtime_mode",
                "runtime": snapshot,
                "generated_at": utc_now(),
            }
        )

    def start(self):
        with self._lock:
            self.current_engine().start()
            snapshot = self.snapshot()
        self._broadcast_snapshot(snapshot)
        return snapshot

    def stop(self):
        with self._lock:
            self.current_engine().stop()
            snapshot = self.snapshot()
        self._broadcast_snapshot(snapshot)
        return snapshot

    def set_mode(self, mode: str):
        normalized = normalize_runtime_mode(mode)
        with self._lock:
            if normalized == self.mode:
                if self._capture_auto_start and not self.current_engine().snapshot().get("running"):
                    self.current_engine().start()
                self._store.set_runtime_config("runtime_mode", self.mode)
                snapshot = self.snapshot()
            else:
                previous = self.current_engine()
                previous.stop()
                self.mode = normalized
                self._store.set_runtime_config("runtime_mode", self.mode)
                if self._capture_auto_start:
                    self.current_engine().start()
                snapshot = self.snapshot()
        self._broadcast_snapshot(snapshot)
        return snapshot

    def set_sniffer_interfaces(self, interfaces=None):
        selected = normalize_interface_selection(interfaces)
        with self._lock:
            previous_interfaces = tuple(self._sniffer.snapshot().get("selected_interfaces") or ())
            was_running = bool(self._sniffer.snapshot().get("running"))
            self._sniffer.set_interfaces(selected)
            self._store.set_runtime_config("sniffer_interfaces", json.dumps(selected))
            self._store.set_runtime_config("sniffer_interface", selected[0] if len(selected) == 1 else "")
            if self.mode == "sniffer" and was_running and tuple(selected) != previous_interfaces:
                self._sniffer.restart()
            snapshot = self.snapshot()
            self._hub.broadcast(
                {
                    "type": "runtime_mode",
                    "runtime": snapshot,
                    "generated_at": utc_now(),
                }
            )
            return snapshot

    def set_sniffer_interface(self, interface: str = ""):
        selected = str(interface or "").strip()
        return self.set_sniffer_interfaces([selected] if selected else [])

    def set_wifi_monitor(self, enabled: bool, interface: str = ""):
        with self._lock:
            self._sniffer.set_wifi_monitor(bool(enabled), interface)
            snapshot = self.snapshot()
        self._broadcast_snapshot(snapshot)
        return snapshot

    def wifi_snapshot(self):
        return self._sniffer.wifi_snapshot()

    def list_honeypot_listeners(self):
        """Listener management is independent of which engine is currently
        active (same reasoning as `set_wifi_monitor` above) - you can create
        or toggle a honeypot listener while the Sniffer is the active mode;
        it just won't have a live thread until honeypot mode is started."""
        return self._honeypot.store.list_honeypot_listeners()

    def create_honeypot_listener(self, proto: str, port, label: str = ""):
        with self._lock:
            snapshot = self._honeypot.create_listener(proto, port, label)
        self._broadcast_snapshot(self.snapshot())
        return snapshot

    def set_honeypot_listener_enabled(self, listener_id: str, enabled: bool):
        with self._lock:
            snapshot = self._honeypot.set_listener_enabled(listener_id, bool(enabled))
        self._broadcast_snapshot(self.snapshot())
        return snapshot
