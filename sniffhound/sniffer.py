from __future__ import annotations

import ipaddress
import math
import re
import socket
import threading
import time
from dataclasses import dataclass, field

from . import netlink
from .anomaly import AnomalyEngine
from .logger import get_capture_logger
from .monitors import evaluate_packet
from .rulesets import classify_packet
from .settings import (
    CAPTURE_BUFFER_BYTES,
    CAPTURE_POLL_TIMEOUT,
    CAPTURE_PROMISCUOUS,
)
from .utils import (
    bytes_to_hex_preview,
    bytes_to_text_preview,
    format_mac,
    is_printable_payload,
    local_ip_candidates,
    normalize_protocol_name,
    normalize_text,
    safe_int,
    stable_flow_key,
    utc_now,
)


ETHERTYPE_VLAN = {0x8100, 0x88A8, 0x9100}
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
ETHERTYPE_ARP = 0x0806
STP_MULTICAST_MAC = "01:80:c2:00:00:00"
LLC_STP_HEADER = b"\x42\x42\x03"
IP_PROTO_TCP = 6
IP_PROTO_UDP = 17
IP_PROTO_SCTP = 132
IP_PROTO_ICMP = 1
IP_PROTO_ICMPV6 = 58
IP_PROTO_IGMP = 2
IP_PROTO_GRE = 47
IP_PROTO_IPV6_HOP_BY_HOP = 0
IP_PROTO_IPV6_ROUTING = 43
IP_PROTO_IPV6_FRAGMENT = 44
IP_PROTO_IPV6_ESP = 50  # IP protocol 50 (ESP) — same number for IPv4 and IPv6, reused for both dispatches below
IP_PROTO_IPV6_AH = 51  # IP protocol 51 (AH) — same number for IPv4 and IPv6, reused for both dispatches below
IP_PROTO_IPV6_DESTINATION = 60
IP_PROTO_IPV6_MOBILITY = 135
IP_PROTO_IPV6_HIP = 139
IP_PROTO_IPV6_SHIM6 = 140
SOL_PACKET = 263
PACKET_ADD_MEMBERSHIP = 1
PACKET_MR_PROMISC = 1
ETH_P_ALL = 0x0003
MONITOR_CACHE_TTL_SECONDS = 2.0
RULESET_CACHE_TTL_SECONDS = 2.0
STATS_BROADCAST_MIN_INTERVAL_SECONDS = 1.0

LOGGER = get_capture_logger()

HTTP_REQUEST_LINE_RE = re.compile(
    r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT|TRACE)\s+(\S+)\s+HTTP/\d\.\d",
    re.IGNORECASE,
)
HTTP_HOST_HEADER_RE = re.compile(r"^Host:\s*([^\r\n]+)", re.IGNORECASE | re.MULTILINE)


def extract_http_request(text: str) -> tuple[str, str, str]:
    if not text:
        return "", "", ""
    match = HTTP_REQUEST_LINE_RE.match(text.strip())
    if not match:
        return "", "", ""
    method = match.group(1).upper()
    path = match.group(2).strip()
    host_match = HTTP_HOST_HEADER_RE.search(text)
    host = host_match.group(1).strip() if host_match else ""
    return method, path, host


def extract_dns_query_name(payload: bytes) -> str:
    try:
        if len(payload) < 12:
            return ""
        is_response = bool(payload[2] & 0x80)
        if is_response:
            # Responses echo the question section too, but src/dst are
            # reversed from the query (server -> client). Only extract from
            # the query itself so the resolver's IP:53 is what gets recorded,
            # not the client's own address and ephemeral port.
            return ""
        qdcount = int.from_bytes(payload[4:6], "big")
        if qdcount < 1:
            return ""
        offset = 12
        labels = []
        while offset < len(payload):
            length = payload[offset]
            if length == 0:
                offset += 1
                break
            if length & 0xC0:
                return ""
            offset += 1
            if offset + length > len(payload):
                return ""
            label = payload[offset : offset + length]
            if not label.isascii():
                return ""
            labels.append(label.decode("ascii"))
            offset += length
            if offset > 512:
                return ""
        name = ".".join(labels).strip(".").lower()
        if not name or not name.isprintable():
            return ""
        return name
    except Exception:
        return ""


def extract_tls_sni(payload: bytes) -> str:
    try:
        if len(payload) < 44 or payload[0] != 0x16:
            return ""
        if payload[5] != 0x01:
            return ""
        pos = 9
        pos += 2 + 32
        if pos >= len(payload):
            return ""
        session_id_len = payload[pos]
        pos += 1 + session_id_len
        if pos + 2 > len(payload):
            return ""
        cipher_len = int.from_bytes(payload[pos : pos + 2], "big")
        pos += 2 + cipher_len
        if pos >= len(payload):
            return ""
        comp_len = payload[pos]
        pos += 1 + comp_len
        if pos + 2 > len(payload):
            return ""
        ext_total_len = int.from_bytes(payload[pos : pos + 2], "big")
        pos += 2
        end = min(pos + ext_total_len, len(payload))
        while pos + 4 <= end:
            ext_type = int.from_bytes(payload[pos : pos + 2], "big")
            ext_len = int.from_bytes(payload[pos + 2 : pos + 4], "big")
            ext_data_start = pos + 4
            if ext_type == 0x0000 and ext_data_start + 2 <= end:
                p = ext_data_start + 2
                if p + 3 <= end:
                    name_type = payload[p]
                    name_len = int.from_bytes(payload[p + 1 : p + 3], "big")
                    p += 3
                    if name_type == 0 and p + name_len <= end:
                        name = payload[p : p + name_len]
                        if name.isascii():
                            return name.decode("ascii").strip().lower()
                return ""
            pos = ext_data_start + ext_len
        return ""
    except Exception:
        return ""


DNS_QTYPE_NAMES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
    16: "TXT", 28: "AAAA", 33: "SRV", 255: "ANY",
}
DNS_RCODE_NAMES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
DHCP_MSG_TYPES = {
    1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 4: "DECLINE",
    5: "ACK", 6: "NAK", 7: "RELEASE", 8: "INFORM",
}
IGMP_TYPE_NAMES = {
    0x11: "membership query",
    0x12: "v1 membership report",
    0x16: "v2 membership report",
    0x17: "leave group",
    0x22: "v3 membership report",
}


def _read_dns_name(payload: bytes, offset: int, *, max_jumps: int = 20) -> tuple[str, int]:
    """Decode a (possibly compressed) DNS name starting at `offset`.

    Returns (name, offset_after_the_name_as_it_appears_at_the_call_site) — the
    second value follows only the FIRST compression pointer encountered (or the
    terminating zero length if there was none), per RFC 1035 §4.1.4, so callers
    can keep walking the rest of the message correctly even when this name used
    compression.
    """
    labels: list[str] = []
    jumps = 0
    resume_at: int | None = None
    pos = offset
    while True:
        if pos < 0 or pos >= len(payload):
            break
        length = payload[pos]
        if length == 0:
            pos += 1
            if resume_at is None:
                resume_at = pos
            break
        if (length & 0xC0) == 0xC0:
            if pos + 1 >= len(payload):
                break
            pointer = ((length & 0x3F) << 8) | payload[pos + 1]
            if resume_at is None:
                resume_at = pos + 2
            jumps += 1
            if jumps > max_jumps or pointer >= len(payload) or pointer == pos:
                break
            pos = pointer
            continue
        pos += 1
        if pos + length > len(payload):
            break
        label = bytes(payload[pos : pos + length])
        pos += length
        try:
            labels.append(label.decode("ascii"))
        except Exception:
            labels.append(label.decode("latin-1", errors="replace"))
        if len(labels) > 128:
            break
    name = ".".join(labels).strip(".").lower()
    if resume_at is None:
        resume_at = pos
    return name, resume_at


def _dns_rdata_preview(rtype: int, rdata: bytes, full_payload: bytes, rdata_offset: int) -> str:
    try:
        if rtype == 1 and len(rdata) == 4:  # A
            return str(ipaddress.IPv4Address(rdata))
        if rtype == 28 and len(rdata) == 16:  # AAAA
            return str(ipaddress.IPv6Address(rdata))
        if rtype in (2, 5, 12):  # NS, CNAME, PTR — a (possibly compressed) name
            name, _ = _read_dns_name(full_payload, rdata_offset)
            return name
        if rtype == 16:  # TXT
            texts = []
            pos = 0
            while pos < len(rdata):
                length = rdata[pos]
                pos += 1
                texts.append(rdata[pos : pos + length].decode("ascii", errors="replace"))
                pos += length
            return " ".join(texts)
        return rdata.hex()[:64]
    except Exception:
        return rdata.hex()[:64] if rdata else ""


def parse_dns_message(payload: bytes) -> dict:
    """Full-ish DNS message parser: question + answer records, for both
    queries AND responses (unlike `extract_dns_query_name`, which only reads
    the query leg and is kept as-is for backward compatibility)."""
    result = {"is_response": False, "rcode": 0, "questions": [], "answers": []}
    try:
        if len(payload) < 12:
            return result
        flags = int.from_bytes(payload[2:4], "big")
        result["is_response"] = bool(flags & 0x8000)
        result["rcode"] = flags & 0x000F
        qdcount = int.from_bytes(payload[4:6], "big")
        ancount = int.from_bytes(payload[6:8], "big")
        offset = 12
        questions = []
        for _ in range(min(qdcount, 32)):
            if offset >= len(payload):
                break
            name, offset = _read_dns_name(payload, offset)
            if offset + 4 > len(payload):
                break
            qtype = int.from_bytes(payload[offset : offset + 2], "big")
            qclass = int.from_bytes(payload[offset + 2 : offset + 4], "big")
            offset += 4
            questions.append({"name": name, "qtype": qtype, "qclass": qclass})
        result["questions"] = questions
        answers = []
        for _ in range(min(ancount, 32)):
            if offset >= len(payload):
                break
            name, offset = _read_dns_name(payload, offset)
            if offset + 10 > len(payload):
                break
            rtype = int.from_bytes(payload[offset : offset + 2], "big")
            ttl = int.from_bytes(payload[offset + 4 : offset + 8], "big")
            rdlength = int.from_bytes(payload[offset + 8 : offset + 10], "big")
            offset += 10
            rdata = payload[offset : offset + rdlength] if offset + rdlength <= len(payload) else b""
            rdata_preview = _dns_rdata_preview(rtype, rdata, payload, offset)
            offset += rdlength
            answers.append({"name": name, "qtype": rtype, "ttl": ttl, "rdata": rdata_preview})
        result["answers"] = answers
    except Exception:
        pass
    return result


def _dns_message_summary(prefix: str, parsed: dict) -> str:
    if parsed.get("questions"):
        question = parsed["questions"][0]
        qtype_name = DNS_QTYPE_NAMES.get(question["qtype"], str(question["qtype"]))
        kind = "response" if parsed.get("is_response") else "query"
        base = f"{prefix} {kind} {question['name']} {qtype_name}"
    else:
        base = f"{prefix} message"
    if parsed.get("is_response"):
        answers = parsed.get("answers") or []
        if answers:
            base += f" -> {answers[0]['rdata']}"
        rcode = parsed.get("rcode") or 0
        if rcode:
            base += f" [{DNS_RCODE_NAMES.get(rcode, str(rcode))}]"
    return base


def decode_nbns_name(encoded: bytes) -> str:
    """Decode an RFC 1002 §4.1 "first-level encoded" NBNS name (32 half-ASCII
    nibble-pair bytes) — an entirely different wire format from DNS labels,
    so this does NOT reuse `_read_dns_name`."""
    try:
        if len(encoded) != 32:
            return ""
        chars = []
        for i in range(0, 32, 2):
            hi = encoded[i] - 0x41
            lo = encoded[i + 1] - 0x41
            if not (0 <= hi <= 15 and 0 <= lo <= 15):
                return ""
            chars.append(chr((hi << 4) | lo))
        return "".join(chars).rstrip("\x00").rstrip()
    except Exception:
        return ""


@dataclass
class CaptureState:
    running: bool = False
    interfaces: list[str] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)
    packets_seen: int = 0
    packets_total_bytes: int = 0
    packets_stored: int = 0
    started_at: str = ""
    last_packet_at: str = ""


def build_base_packet(
    now: str,
    interface: str,
    data: bytes,
    payload: bytes,
    *,
    eth_src: str = "",
    eth_dst: str = "",
    eth_type: int = 0,
) -> dict:
    """Build the flat ~35-key packet dict shared by every capture path.

    Extracted out of `Sniffer._new_packet` (which is now a thin wrapper around
    this) so `wifi.py`'s 802.11 capture path can build a schema-compatible
    packet dict without duplicating this literal or depending on a `Sniffer`
    instance.
    """
    return {
        "session_id": 0,
        "interface": str(interface or "").strip(),
        "eth_src": eth_src,
        "eth_dst": eth_dst,
        "eth_type": eth_type,
        "ip_version": 0,
        "src_ip": "",
        "dst_ip": "",
        "proto": "unknown",
        "src_port": 0,
        "dst_port": 0,
        "ttl": 0,
        "hop_limit": 0,
        "length": len(data),
        "payload_len": len(payload),
        "state": "filtered" if not payload else "open",
        "scan_state": "active",
        "tcp_flags": "",
        "icmp_type": 0,
        "icmp_code": 0,
        "arp_opcode": 0,
        "summary": "",
        "payload_text": "",
        "payload_hex": bytes_to_hex_preview(payload),
        "banner_text": "",
        "direction": "unknown",
        "domain": "",
        "domain_source": "",
        "http_method": "",
        "http_path": "",
        "http_host": "",
        "raw_packet": data[:],
        "created_at": now,
        "updated_at": now,
    }


class Sniffer:
    def __init__(self, store, hub, *, interfaces: tuple[str, ...] = ()):
        self.store = store
        self.hub = hub
        self._allowed_interfaces = tuple(
            str(interface).strip()
            for interface in (interfaces or ())
            if str(interface).strip()
        )
        self._selected_interfaces: tuple[str, ...] = ()
        self._stop_event = threading.Event()
        self._threads: list[threading.Thread] = []
        self._state_lock = threading.RLock()
        self.state = CaptureState()
        self._local_ips = local_ip_candidates()
        self._monitor_cache: list[dict] = []
        self._monitor_filter_enabled = True
        self._monitor_cache_at = 0.0
        self._ruleset_cache: list[dict] = []
        self._ruleset_cache_at = 0.0
        self._last_stats_broadcast_at = 0.0
        self._anomaly = AnomalyEngine()
        self._wifi_stop_event = threading.Event()
        self._wifi_thread: threading.Thread | None = None
        self._wifi_lock = threading.RLock()
        self._wifi_state: dict = {"enabled": False, "interface": "", "error": ""}

    def _discover_interfaces(self) -> list[str]:
        try:
            names = [name for _, name in socket.if_nameindex()]
            if names:
                return names
        except Exception:
            pass
        return ["lo"]

    def list_available_interfaces(self) -> list[str]:
        if self._allowed_interfaces:
            return list(self._allowed_interfaces)
        return self._discover_interfaces()

    def list_interfaces(self) -> list[str]:
        if self._selected_interfaces:
            return list(self._selected_interfaces)
        return self.list_available_interfaces()

    def set_interfaces(self, interfaces=None):
        raw_items = interfaces
        if raw_items is None:
            raw_items = []
        elif isinstance(raw_items, str):
            raw_items = [raw_items]

        available = set(self.list_available_interfaces())
        normalized: list[str] = []
        seen: set[str] = set()
        for item in raw_items:
            value = str(item or "").strip()
            if not value or value in seen:
                continue
            if value not in available:
                raise ValueError(f"Unknown interface: {value}")
            normalized.append(value)
            seen.add(value)
        with self._state_lock:
            self._selected_interfaces = tuple(normalized)
        return self.snapshot()

    def set_interface(self, interface: str = ""):
        selected = str(interface or "").strip()
        return self.set_interfaces([selected] if selected else [])

    def selected_interfaces(self) -> list[str]:
        with self._state_lock:
            return list(self._selected_interfaces)

    def selected_interface(self) -> str:
        selected = self.selected_interfaces()
        return selected[0] if len(selected) == 1 else ""

    def selected_interfaces_label(self) -> str:
        selected = self.selected_interfaces()
        if not selected:
            return "all interfaces"
        if len(selected) == 1:
            return selected[0]
        return f"{len(selected)} interfaces"

    def snapshot(self):
        with self._state_lock:
            selected = list(self._selected_interfaces)
            available = self.list_available_interfaces()
            active_threads = sum(1 for thread in self._threads if thread.is_alive())
            errors = dict(self.state.errors)
            capture_state = "idle"
            if self.state.running and active_threads > 0:
                capture_state = "running"
            elif self.state.running and errors:
                capture_state = "blocked"
            return {
                "running": bool(self.state.running),
                "capture_state": capture_state,
                "interfaces": list(self.state.interfaces),
                "available_interfaces": available,
                "selected_interfaces": selected,
                "selected_interface": selected[0] if len(selected) == 1 else "",
                "errors": errors,
                "packets_seen": int(self.state.packets_seen),
                "packets_total_bytes": int(self.state.packets_total_bytes),
                "packets_stored": int(self.state.packets_stored),
                "started_at": self.state.started_at,
                "last_packet_at": self.state.last_packet_at,
                "active_threads": active_threads,
                "wifi": self.wifi_snapshot(),
            }

    def start(self):
        with self._state_lock:
            if self.state.running:
                return self.snapshot()
            self._stop_event.clear()
            self.state.running = True
            self.state.interfaces = self.list_interfaces()
            self.state.errors = {}
            self.state.started_at = utc_now()
            self.state.last_packet_at = ""
            self.state.packets_seen = 0
            self.state.packets_total_bytes = 0
            self.state.packets_stored = 0
            threads = []
            for interface in self.state.interfaces:
                thread = threading.Thread(
                    target=self._capture_worker,
                    args=(interface,),
                    name=f"sniffhound-capture-{interface}",
                    daemon=True,
                )
                thread.start()
                threads.append(thread)
            self._threads = threads
        return self.snapshot()

    def stop(self):
        self._stop_event.set()
        with self._state_lock:
            self.state.running = False
        for thread in list(self._threads):
            if thread.is_alive():
                thread.join(timeout=0.8)
        self._threads = []
        return self.snapshot()

    def restart(self):
        self.stop()
        return self.start()

    def wifi_snapshot(self) -> dict:
        with self._wifi_lock:
            state = dict(self._wifi_state)
        try:
            eligible = [
                interface
                for interface in self._discover_interfaces()
                if netlink.is_wireless_interface(interface)
            ]
        except Exception:
            eligible = []
        state["eligible_interfaces"] = eligible
        return state

    def set_wifi_monitor(self, enabled: bool, interface: str = "") -> dict:
        """Manually toggle 802.11 monitor-mode capture on a wireless interface.

        Independent of start()/stop()/restart() — this must keep working (and
        keep running) regardless of whether the normal Ethernet/IP sniffer or
        the honeypot engine is the currently active RuntimeController mode.
        """
        enabled = bool(enabled)
        interface = str(interface or "").strip()
        with self._wifi_lock:
            if not enabled:
                self._wifi_stop_event.set()
                thread = self._wifi_thread
                if thread is not None and thread.is_alive():
                    thread.join(timeout=1.5)
                self._wifi_thread = None
                target_interface = interface or str(self._wifi_state.get("interface") or "")
                error = ""
                if target_interface:
                    try:
                        netlink.set_monitor_mode(target_interface, enabled=False)
                    except netlink.WifiMonitorModeError as exc:
                        error = str(exc)
                self._wifi_state = {"enabled": False, "interface": "", "error": error}
                return self.wifi_snapshot()

            if self._wifi_state.get("enabled"):
                raise ValueError("WiFi monitor mode is already enabled")
            if not interface:
                raise ValueError("interface is required to enable WiFi monitor mode")
            if not netlink.is_wireless_interface(interface):
                raise ValueError(f"{interface} is not a wireless interface")

            try:
                netlink.set_monitor_mode(interface, enabled=True)
            except netlink.WifiMonitorModeError as exc:
                self._wifi_state = {"enabled": False, "interface": "", "error": str(exc)}
                raise ValueError(str(exc)) from exc

            self._wifi_stop_event = threading.Event()
            thread = threading.Thread(
                target=self._wifi_capture_worker,
                args=(interface,),
                name=f"sniffhound-wifi-{interface}",
                daemon=True,
            )
            self._wifi_state = {"enabled": True, "interface": interface, "error": ""}
            thread.start()
            self._wifi_thread = thread
            return self.wifi_snapshot()

    def _wifi_capture_worker(self, interface: str):
        from . import wifi as wifi_module

        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, CAPTURE_BUFFER_BYTES)
            sock.settimeout(CAPTURE_POLL_TIMEOUT)
            sock.bind((interface, 0))
        except Exception as exc:
            with self._wifi_lock:
                self._wifi_state["error"] = f"wifi capture socket unavailable: {exc}"
            return

        stop_event = self._wifi_stop_event
        while not stop_event.is_set():
            try:
                data, _ = sock.recvfrom(CAPTURE_BUFFER_BYTES)
            except socket.timeout:
                continue
            except OSError:
                if stop_event.is_set():
                    break
                continue
            if not data:
                continue
            try:
                packet = wifi_module.parse_80211_frame(data, interface=interface)
            except Exception:
                LOGGER.exception("Failed to parse 802.11 frame on %s", interface)
                continue
            if not packet:
                continue
            packet = self._finalize_packet(packet)
            try:
                self._store_packet(packet)
            except Exception:
                LOGGER.exception("Failed to process WiFi frame on %s", interface)

        try:
            sock.close()
        except Exception:
            pass

    def emergency_wifi_restore(self):
        """Best-effort restore to managed mode, meant to run from `atexit` so a
        crashed/killed process doesn't leave the user's only WiFi adapter stuck
        in monitor mode with no connectivity."""
        try:
            with self._wifi_lock:
                enabled = bool(self._wifi_state.get("enabled"))
                interface = str(self._wifi_state.get("interface") or "")
            if enabled and interface:
                self._wifi_stop_event.set()
                netlink.set_monitor_mode(interface, enabled=False)
        except Exception:
            pass

    def _set_error(self, interface: str, message: str):
        with self._state_lock:
            self.state.errors[str(interface)] = str(message)

    def _touch_packet(self, packet: dict, *, stored: bool = False):
        payload_len = safe_int(packet.get("payload_len", 0), 0)
        length = safe_int(packet.get("length", 0), 0)
        with self._state_lock:
            self.state.packets_seen += 1
            self.state.packets_total_bytes += max(length, payload_len)
            if stored:
                self.state.packets_stored += 1
            self.state.last_packet_at = utc_now()

    def _broadcast_packet(self, packet: dict, *, persisted: bool = True):
        event = {
            "type": "packet",
            "packet": packet,
            "persisted": bool(persisted),
            "generated_at": utc_now(),
        }
        self.hub.broadcast(event)
        self._broadcast_stats()

    def _broadcast_stats_throttled(self):
        now = time.monotonic()
        if now - self._last_stats_broadcast_at < STATS_BROADCAST_MIN_INTERVAL_SECONDS:
            return
        self._last_stats_broadcast_at = now
        self._broadcast_stats()

    def _broadcast_stats(self):
        self.hub.broadcast(
            {
                "type": "stats_update",
                "stats": {
                    "packets_seen": self.state.packets_seen,
                    "packets_total_bytes": self.state.packets_total_bytes,
                    "packets_stored": self.state.packets_stored,
                },
                "generated_at": utc_now(),
            }
        )

    def _get_monitor_context(self):
        now = time.monotonic()
        if now - self._monitor_cache_at >= MONITOR_CACHE_TTL_SECONDS:
            try:
                self._monitor_cache = self.store.list_monitors()
                self._monitor_filter_enabled = self.store.get_monitor_filter_enabled()
            except Exception:
                LOGGER.exception("Failed to refresh monitors")
            self._monitor_cache_at = now
        return self._monitor_cache, self._monitor_filter_enabled

    def _get_rulesets(self):
        now = time.monotonic()
        if now - self._ruleset_cache_at >= RULESET_CACHE_TTL_SECONDS:
            try:
                self._ruleset_cache = self.store.list_rulesets()
            except Exception:
                LOGGER.exception("Failed to refresh rulesets")
            self._ruleset_cache_at = now
        return self._ruleset_cache

    def _capture_worker(self, interface: str):
        try:
            sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, CAPTURE_BUFFER_BYTES)
            sock.settimeout(CAPTURE_POLL_TIMEOUT)
            try:
                sock.bind((interface, 0))
            except Exception as exc:
                self._set_error(interface, f"bind failed: {exc}")
            if CAPTURE_PROMISCUOUS:
                self._enable_promiscuous(sock, interface)
        except PermissionError as exc:
            self._set_error(interface, f"permission denied: {exc}")
            return
        except Exception as exc:
            self._set_error(interface, f"socket unavailable: {exc}")
            return

        while not self._stop_event.is_set():
            try:
                data, _ = sock.recvfrom(CAPTURE_BUFFER_BYTES)
            except socket.timeout:
                continue
            except OSError as exc:
                if self._stop_event.is_set():
                    break
                self._set_error(interface, str(exc))
                continue
            if not data:
                continue
            packet = self.parse_packet(data, interface=interface)
            if not packet:
                continue
            try:
                self._store_packet(packet)
            except Exception:
                LOGGER.exception("Failed to process captured packet on %s", interface)

        try:
            sock.close()
        except Exception:
            pass

    def _enable_promiscuous(self, sock, interface: str):
        try:
            ifindex = socket.if_nametoindex(interface)
        except Exception:
            return
        try:
            ifindex_bytes = int(ifindex).to_bytes(4, "little", signed=True)
            req_type = int(PACKET_MR_PROMISC).to_bytes(2, "little", signed=False)
            req_alen = (0).to_bytes(2, "little", signed=False)
            req_addr = bytes(8)
            sock.setsockopt(SOL_PACKET, PACKET_ADD_MEMBERSHIP, ifindex_bytes + req_type + req_alen + req_addr)
        except Exception as exc:
            self._set_error(interface, f"promiscuous mode unavailable: {exc}")


    def _store_packet(self, packet: dict):
        rulesets = self._get_rulesets()
        matches = classify_packet(packet, rulesets)
        monitors, filter_enabled = self._get_monitor_context()
        monitor_hits = evaluate_packet(packet, monitors) if filter_enabled else []
        # Anomaly detectors run unconditionally, regardless of filter_enabled —
        # a rate/state-based detector that only ever saw already-matched
        # traffic could never build a useful baseline.
        try:
            anomaly_hits = self._anomaly.evaluate(packet, monitors)
        except Exception:
            LOGGER.exception("Anomaly detection failed")
            anomaly_hits = []
        if anomaly_hits:
            monitor_hits = list(monitor_hits) + list(anomaly_hits)
        tags = self._build_packet_tags(packet, matches, monitor_hits)
        packet["rule_hits"] = matches
        packet["monitor_hits"] = monitor_hits
        packet["tags"] = tags
        packet["banner_text"] = packet.get("banner_text") or packet.get("payload_text") or ""

        detected = bool(monitor_hits) or not filter_enabled
        if detected:
            saved = self.store.register_packet(packet)
            self._touch_packet(saved or packet, stored=True)
            self._broadcast_packet(saved or packet, persisted=True)
            self._record_intel(packet)
        else:
            # Undetected traffic can arrive at wire speed; broadcasting a full
            # "packet" event for every one of them would flood connected
            # dashboards. Only the counters need to stay live for this case,
            # and even those are time-throttled so the broadcast rate has a
            # hard ceiling regardless of how fast packets arrive.
            self._touch_packet(packet, stored=False)
            self._broadcast_stats_throttled()

        if self.state.packets_seen % 50 == 0:
            self.store.trim_oversized_tables()

    def _record_intel(self, packet: dict):
        domain = str(packet.get("domain") or "").strip()
        if domain:
            try:
                self.store.record_domain(
                    name=domain,
                    source=str(packet.get("domain_source") or "").strip(),
                    ip=str(packet.get("dst_ip") or packet.get("src_ip") or "").strip(),
                    port=safe_int(packet.get("dst_port") or packet.get("src_port") or 0, 0),
                    proto=normalize_protocol_name(packet.get("proto")),
                )
            except Exception:
                LOGGER.exception("Failed to record domain intel")

        path = str(packet.get("http_path") or "").strip()
        if path:
            try:
                self.store.record_path(
                    path=path,
                    method=str(packet.get("http_method") or "GET").strip().upper() or "GET",
                    host=str(packet.get("http_host") or "").strip(),
                    ip=str(packet.get("dst_ip") or packet.get("src_ip") or "").strip(),
                    port=safe_int(packet.get("dst_port") or packet.get("src_port") or 0, 0),
                )
            except Exception:
                LOGGER.exception("Failed to record path intel")

    def _build_packet_tags(self, packet: dict, matches: list[dict], monitor_hits: list[dict] | None = None) -> list[dict]:
        tags = [
            {"key": "proto", "value": normalize_protocol_name(packet.get("proto"))},
            {"key": "state", "value": str(packet.get("state") or "open").strip().lower() or "open"},
            {"key": "direction", "value": str(packet.get("direction") or "unknown").strip().lower() or "unknown"},
        ]
        if packet.get("src_port"):
            tags.append({"key": "src_port", "value": str(packet.get("src_port"))})
        if packet.get("dst_port"):
            tags.append({"key": "dst_port", "value": str(packet.get("dst_port"))})
        for match in matches:
            label = str(match.get("label") or match.get("tag") or match.get("rule_name") or "").strip()
            if label:
                tags.append({"key": "rule", "value": label})
        for hit in monitor_hits or []:
            label = str(hit.get("label") or hit.get("tag") or hit.get("monitor_name") or "").strip()
            if label:
                tags.append({"key": "monitor", "value": label})
            monitor_id = str(hit.get("monitor_id") or "").strip()
            if monitor_id:
                tags.append({"key": "monitor_id", "value": monitor_id})
            detail = str(hit.get("detail") or "").strip()
            if detail:
                tags.append({"key": "detail", "value": detail})
        return tags

    def parse_packet(self, data: bytes, *, interface: str = "") -> dict | None:
        if not data:
            return None
        now = utc_now()
        if self._looks_like_raw_ipv4(data):
            packet = self._new_packet(now, interface, data, data, eth_type=ETHERTYPE_IPV4)
            self._parse_ipv4(packet, data)
            return self._finalize_packet(packet)
        if self._looks_like_raw_ipv6(data):
            packet = self._new_packet(now, interface, data, data, eth_type=ETHERTYPE_IPV6)
            self._parse_ipv6(packet, data)
            return self._finalize_packet(packet)
        if len(data) < 14:
            return None
        frame = memoryview(data)
        dst_mac = format_mac(frame[0:6])
        src_mac = format_mac(frame[6:12])
        eth_type = int.from_bytes(frame[12:14], "big")
        offset = 14
        while eth_type in ETHERTYPE_VLAN and len(frame) >= offset + 4:
            eth_type = int.from_bytes(frame[offset + 2 : offset + 4], "big")
            offset += 4
        payload = bytes(frame[offset:])
        packet = self._new_packet(
            now,
            interface,
            data,
            payload,
            eth_src=src_mac,
            eth_dst=dst_mac,
            eth_type=eth_type,
        )
        if eth_type == ETHERTYPE_IPV4:
            self._parse_ipv4(packet, payload)
        elif eth_type == ETHERTYPE_IPV6:
            self._parse_ipv6(packet, payload)
        elif eth_type == ETHERTYPE_ARP:
            self._parse_arp(packet, payload)
        elif self._is_stp_bpdu(packet, payload):
            self._parse_stp(packet, payload)
        else:
            packet["summary"] = f"EtherType 0x{eth_type:04x} payload {len(payload)} bytes"
            packet["payload_text"] = bytes_to_text_preview(payload)
            packet["banner_text"] = packet["payload_text"]
        return self._finalize_packet(packet)

    def _new_packet(
        self,
        now: str,
        interface: str,
        data: bytes,
        payload: bytes,
        *,
        eth_src: str = "",
        eth_dst: str = "",
        eth_type: int = 0,
    ) -> dict:
        return build_base_packet(
            now, interface, data, payload, eth_src=eth_src, eth_dst=eth_dst, eth_type=eth_type
        )

    def _finalize_packet(self, packet: dict) -> dict:
        packet["flow_key"] = stable_flow_key(
            packet.get("proto") or "unknown",
            packet.get("src_ip") or packet.get("eth_src") or "unknown",
            packet.get("src_port") or 0,
            packet.get("dst_ip") or packet.get("eth_dst") or "unknown",
            packet.get("dst_port") or 0,
        )
        packet["direction"] = self._direction_for(packet)
        packet["banner_text"] = packet.get("banner_text") or packet.get("payload_text") or ""
        packet["state"] = packet.get("state") or ("open" if packet.get("payload_len", 0) else "filtered")
        packet["payload_text"] = packet.get("payload_text") or ""
        packet["payload_hex"] = packet.get("payload_hex") or ""
        packet["summary"] = packet.get("summary") or self._fallback_summary(packet)
        return packet

    def _looks_like_raw_ipv4(self, data: bytes) -> bool:
        if len(data) < 20 or (data[0] >> 4) != 4:
            return False
        header_length = (data[0] & 0x0F) * 4
        if header_length < 20 or header_length > len(data):
            return False
        total_length = int.from_bytes(data[2:4], "big")
        if total_length and total_length < header_length:
            return False
        try:
            ipaddress.IPv4Address(data[12:16])
            ipaddress.IPv4Address(data[16:20])
        except Exception:
            return False
        return self._ipv4_checksum_is_valid(data[:header_length])

    def _looks_like_raw_ipv6(self, data: bytes) -> bool:
        if len(data) < 40 or (data[0] >> 4) != 6:
            return False
        try:
            ipaddress.IPv6Address(data[8:24])
            ipaddress.IPv6Address(data[24:40])
        except Exception:
            return False
        return True

    def _ipv4_checksum_is_valid(self, header: bytes) -> bool:
        if len(header) < 20 or (len(header) % 2) != 0:
            return False
        total = 0
        for index in range(0, len(header), 2):
            total += int.from_bytes(header[index : index + 2], "big")
        while total > 0xFFFF:
            total = (total & 0xFFFF) + (total >> 16)
        return (total & 0xFFFF) == 0xFFFF

    def _is_stp_bpdu(self, packet: dict, payload: bytes) -> bool:
        return (
            str(packet.get("eth_dst") or "").lower() == STP_MULTICAST_MAC
            and len(payload) >= len(LLC_STP_HEADER)
            and payload[:3] == LLC_STP_HEADER
        )

    def _direction_for(self, packet: dict) -> str:
        src_ip = str(packet.get("src_ip") or "").strip()
        dst_ip = str(packet.get("dst_ip") or "").strip()
        local_ips = self._local_ips
        if src_ip in local_ips and dst_ip and dst_ip not in local_ips:
            return "outbound"
        if dst_ip in local_ips and src_ip and src_ip not in local_ips:
            return "inbound"
        if src_ip in local_ips and dst_ip in local_ips:
            return "local"
        return "unknown"

    def _fallback_summary(self, packet: dict) -> str:
        proto = normalize_protocol_name(packet.get("proto"))
        src = packet.get("src_ip") or packet.get("eth_src") or "?"
        dst = packet.get("dst_ip") or packet.get("eth_dst") or "?"
        port_text = ""
        src_port = safe_int(packet.get("src_port", 0), 0)
        dst_port = safe_int(packet.get("dst_port", 0), 0)
        if src_port or dst_port:
            port_text = f" {src_port}->{dst_port}"
        return f"{proto.upper()} {src}{port_text} → {dst}"

    def _parse_ipv4(self, packet: dict, payload: bytes):
        if len(payload) < 20:
            packet["summary"] = "IPv4 packet"
            packet["payload_text"] = bytes_to_text_preview(payload)
            packet["banner_text"] = packet["payload_text"]
            return
        version_ihl = payload[0]
        ihl = (version_ihl & 0x0F) * 4
        total_length = int.from_bytes(payload[2:4], "big")
        packet["ip_version"] = 4
        packet["ttl"] = payload[8]
        proto = payload[9]
        packet["src_ip"] = str(ipaddress.IPv4Address(payload[12:16]))
        packet["dst_ip"] = str(ipaddress.IPv4Address(payload[16:20]))
        body = payload[ihl:total_length] if total_length > ihl else payload[ihl:]
        if proto == IP_PROTO_TCP:
            self._parse_tcp(packet, body)
        elif proto == IP_PROTO_UDP:
            self._parse_udp(packet, body)
        elif proto == IP_PROTO_SCTP:
            self._parse_sctp(packet, body)
        elif proto == IP_PROTO_ICMP:
            self._parse_icmp(packet, body)
        elif proto == IP_PROTO_IGMP:
            self._parse_igmp(packet, body)
        elif proto == IP_PROTO_GRE:
            self._parse_gre(packet, body)
        elif proto == IP_PROTO_IPV6_ESP:
            self._parse_esp(packet, body, ip_version=4)
        elif proto == IP_PROTO_IPV6_AH:
            self._parse_ah(packet, body, ip_version=4)
        else:
            packet["proto"] = "unknown"
            packet["summary"] = f"IPv4 protocol {proto} {packet['src_ip']} → {packet['dst_ip']}"
            packet["payload_text"] = bytes_to_text_preview(body)
            packet["banner_text"] = packet["payload_text"]
        if not packet.get("summary"):
            packet["summary"] = self._fallback_summary(packet)

    def _parse_ipv6(self, packet: dict, payload: bytes):
        if len(payload) < 40:
            packet["summary"] = "IPv6 packet"
            packet["payload_text"] = bytes_to_text_preview(payload)
            packet["banner_text"] = packet["payload_text"]
            return
        packet["ip_version"] = 6
        packet["hop_limit"] = payload[7]
        packet["src_ip"] = str(ipaddress.IPv6Address(payload[8:24]))
        packet["dst_ip"] = str(ipaddress.IPv6Address(payload[24:40]))
        next_header, body, detail = self._unwrap_ipv6_transport(payload)
        if next_header == IP_PROTO_TCP:
            self._parse_tcp(packet, body, ip_version=6)
        elif next_header == IP_PROTO_UDP:
            self._parse_udp(packet, body, ip_version=6)
        elif next_header == IP_PROTO_SCTP:
            self._parse_sctp(packet, body, ip_version=6)
        elif next_header == IP_PROTO_ICMPV6:
            self._parse_icmp(packet, body, ipv6=True)
        elif next_header == IP_PROTO_IPV6_ESP:
            self._parse_esp(packet, body, ip_version=6)
        elif next_header == IP_PROTO_IPV6_AH:
            self._parse_ah(packet, body, ip_version=6)
        else:
            packet["proto"] = "unknown"
            packet["summary"] = f"IPv6 {detail} {packet['src_ip']} → {packet['dst_ip']}"
            packet["payload_text"] = bytes_to_text_preview(body)
            packet["banner_text"] = packet["payload_text"]
        if not packet.get("summary"):
            packet["summary"] = self._fallback_summary(packet)

    def _unwrap_ipv6_transport(self, payload: bytes) -> tuple[int | None, bytes, str]:
        next_header = payload[6]
        offset = 40

        # Walk common IPv6 extension headers so we still reach the transport payload.
        while True:
            if next_header in {
                IP_PROTO_IPV6_HOP_BY_HOP,
                IP_PROTO_IPV6_ROUTING,
                IP_PROTO_IPV6_DESTINATION,
                IP_PROTO_IPV6_MOBILITY,
                IP_PROTO_IPV6_HIP,
                IP_PROTO_IPV6_SHIM6,
            }:
                if len(payload) < offset + 2:
                    return None, payload[offset:], "truncated IPv6 extension"
                header_length = (payload[offset + 1] + 1) * 8
                if header_length <= 0 or len(payload) < offset + header_length:
                    return None, payload[offset:], "truncated IPv6 extension"
                next_header = payload[offset]
                offset += header_length
                continue
            if next_header == IP_PROTO_IPV6_FRAGMENT:
                if len(payload) < offset + 8:
                    return None, payload[offset:], "truncated IPv6 fragment"
                fragment_offset = ((int.from_bytes(payload[offset + 2 : offset + 4], "big")) >> 3) & 0x1FFF
                next_header = payload[offset]
                offset += 8
                if fragment_offset:
                    return None, payload[offset:], "non-initial IPv6 fragment"
                continue
            if next_header == IP_PROTO_IPV6_AH:
                # Hand off to _parse_ah rather than walking past it here, so IPv6
                # AH packets get the same SPI/seq extraction as IPv4 AH packets
                # (it does its own inner-protocol dispatch on the AH-stripped body).
                return IP_PROTO_IPV6_AH, payload[offset:], "AH"
            if next_header == IP_PROTO_IPV6_ESP:
                return IP_PROTO_IPV6_ESP, payload[offset:], "ESP"
            break

        return next_header, payload[offset:], f"protocol {next_header}"

    def _parse_arp(self, packet: dict, payload: bytes):
        if len(payload) < 28:
            packet["proto"] = "arp"
            packet["summary"] = "ARP packet"
            packet["payload_text"] = bytes_to_text_preview(payload)
            packet["banner_text"] = packet["payload_text"]
            return
        packet["proto"] = "arp"
        packet["arp_opcode"] = int.from_bytes(payload[6:8], "big")
        packet["src_ip"] = str(ipaddress.IPv4Address(payload[14:18]))
        packet["dst_ip"] = str(ipaddress.IPv4Address(payload[24:28]))
        packet["src_port"] = 0
        packet["dst_port"] = 0
        packet["summary"] = f"ARP {packet['src_ip']} → {packet['dst_ip']}"
        packet["payload_text"] = bytes_to_text_preview(payload)
        packet["banner_text"] = packet["payload_text"] or packet["summary"]

    def _parse_stp(self, packet: dict, payload: bytes):
        packet["proto"] = "stp"
        packet["summary"] = "STP BPDU"
        packet["payload_text"] = bytes_to_text_preview(payload)
        packet["banner_text"] = packet["payload_text"] or packet["summary"]

    def _parse_tcp(self, packet: dict, body: bytes, *, ip_version: int = 4):
        if len(body) < 20:
            packet["proto"] = "tcp"
            packet["summary"] = "TCP packet"
            packet["payload_text"] = bytes_to_text_preview(body)
            packet["banner_text"] = packet["payload_text"]
            return
        packet["proto"] = "tcp"
        packet["src_port"] = int.from_bytes(body[0:2], "big")
        packet["dst_port"] = int.from_bytes(body[2:4], "big")
        data_offset = (body[12] >> 4) * 4
        flags_byte = body[13]
        flags = []
        for mask, name in (
            (0x01, "FIN"),
            (0x02, "SYN"),
            (0x04, "RST"),
            (0x08, "PSH"),
            (0x10, "ACK"),
            (0x20, "URG"),
            (0x40, "ECE"),
            (0x80, "CWR"),
        ):
            if flags_byte & mask:
                flags.append(name)
        packet["tcp_flags"] = ",".join(flags)
        payload = body[data_offset:] if data_offset and len(body) >= data_offset else body[20:]
        if (packet["src_port"] == 53 or packet["dst_port"] == 53) and len(payload) > 2:
            # DNS-over-TCP (RFC 1035 §4.2.2): a 2-byte big-endian length prefix
            # precedes the message. Only take this path if it actually looks
            # like a DNS message, so unrelated TCP/53 traffic still falls
            # through to the generic handling below.
            prefix_len = int.from_bytes(payload[0:2], "big")
            dns_payload = payload[2 : 2 + prefix_len] if prefix_len and prefix_len <= len(payload) - 2 else payload[2:]
            parsed_dns = parse_dns_message(dns_payload)
            if parsed_dns.get("questions") or parsed_dns.get("answers"):
                self._apply_dns_result(packet, dns_payload, prefix="DNS", source="dns")
                if ip_version == 6 and not packet.get("hop_limit"):
                    packet["hop_limit"] = 64
                return
        packet["payload_text"] = self._interpret_payload(packet, payload)
        packet["banner_text"] = packet["payload_text"] or self._classify_tcp_banner(packet, payload)
        packet["summary"] = packet["banner_text"] or f"TCP {packet['src_ip']}:{packet['src_port']} → {packet['dst_ip']}:{packet['dst_port']}"
        if ip_version == 6 and not packet.get("hop_limit"):
            packet["hop_limit"] = 64
        if len(payload) >= 1 and payload[:1] == b"\x16":
            packet["banner_text"] = packet["banner_text"] or "TLS handshake"
            sni = extract_tls_sni(payload)
            if sni:
                packet["domain"] = sni
                packet["domain_source"] = "tls_sni"
        method, path, host = extract_http_request(packet["payload_text"])
        if method:
            packet["http_method"] = method
            packet["http_path"] = path
            packet["http_host"] = host
            if host:
                packet["domain"] = host
                packet["domain_source"] = "http_host"

    def _parse_udp(self, packet: dict, body: bytes, *, ip_version: int = 4):
        if len(body) < 8:
            packet["proto"] = "udp"
            packet["summary"] = "UDP packet"
            packet["payload_text"] = bytes_to_text_preview(body)
            packet["banner_text"] = packet["payload_text"]
            return
        packet["proto"] = "udp"
        packet["src_port"] = int.from_bytes(body[0:2], "big")
        packet["dst_port"] = int.from_bytes(body[2:4], "big")
        length = int.from_bytes(body[4:6], "big")
        payload = body[8:length] if length > 8 and length <= len(body) else body[8:]
        packet["payload_text"] = self._interpret_payload(packet, payload)
        packet["banner_text"] = packet["payload_text"] or self._classify_udp_banner(packet, payload)
        packet["summary"] = packet["banner_text"] or f"UDP {packet['src_ip']}:{packet['src_port']} → {packet['dst_ip']}:{packet['dst_port']}"
        if ip_version == 6 and not packet.get("hop_limit"):
            packet["hop_limit"] = 64
        src_port = packet["src_port"]
        dst_port = packet["dst_port"]
        if src_port == 53 or dst_port == 53:
            self._apply_dns_result(packet, payload, prefix="DNS", source="dns")
        elif src_port in (67, 68) or dst_port in (67, 68):
            self._parse_dhcp(packet, payload)
        elif src_port == 5353 or dst_port == 5353:
            packet["proto"] = "mdns"
            self._apply_dns_result(packet, payload, prefix="mDNS", source="mdns")
        elif src_port == 5355 or dst_port == 5355:
            packet["proto"] = "llmnr"
            self._apply_dns_result(packet, payload, prefix="LLMNR", source="llmnr")
        elif src_port == 137 or dst_port == 137:
            self._parse_nbns(packet, payload)

    def _parse_sctp(self, packet: dict, body: bytes, *, ip_version: int = 4):
        if len(body) < 12:
            packet["proto"] = "sctp"
            packet["summary"] = "SCTP packet"
            packet["payload_text"] = bytes_to_text_preview(body)
            packet["banner_text"] = packet["payload_text"]
            return
        packet["proto"] = "sctp"
        packet["src_port"] = int.from_bytes(body[0:2], "big")
        packet["dst_port"] = int.from_bytes(body[2:4], "big")
        payload = body[12:]
        packet["payload_text"] = self._interpret_payload(packet, payload)
        packet["banner_text"] = packet["payload_text"]
        packet["summary"] = packet["banner_text"] or f"SCTP {packet['src_ip']}:{packet['src_port']} → {packet['dst_ip']}:{packet['dst_port']}"
        if ip_version == 6 and not packet.get("hop_limit"):
            packet["hop_limit"] = 64

    def _parse_icmp(self, packet: dict, body: bytes, *, ipv6: bool = False):
        if len(body) < 4:
            packet["proto"] = "icmpv6" if ipv6 else "icmp"
            packet["summary"] = "ICMP packet"
            packet["payload_text"] = bytes_to_text_preview(body)
            packet["banner_text"] = packet["payload_text"]
            return
        packet["proto"] = "icmpv6" if ipv6 else "icmp"
        packet["icmp_type"] = body[0]
        packet["icmp_code"] = body[1]
        packet["payload_text"] = self._interpret_payload(packet, body[4:])
        packet["banner_text"] = packet["payload_text"] or self._classify_icmp_banner(packet)
        packet["summary"] = packet["banner_text"] or f"{packet['proto'].upper()} type {packet['icmp_type']} code {packet['icmp_code']}"

    def _parse_igmp(self, packet: dict, body: bytes):
        packet["proto"] = "igmp"
        if len(body) < 8:
            packet["summary"] = "IGMP packet"
            packet["banner_text"] = packet["summary"]
            packet["payload_text"] = bytes_to_text_preview(body)
            return
        msg_type = body[0]
        type_name = IGMP_TYPE_NAMES.get(msg_type, f"type 0x{msg_type:02x}")
        try:
            group = str(ipaddress.IPv4Address(body[4:8]))
        except Exception:
            group = ""
        summary = f"IGMP {type_name}"
        if group and group != "0.0.0.0":
            summary += f" group={group}"
        packet["summary"] = summary
        packet["banner_text"] = summary
        packet["payload_text"] = summary

    def _parse_gre(self, packet: dict, body: bytes):
        packet["proto"] = "gre"
        if len(body) < 4:
            packet["summary"] = "GRE packet"
            packet["banner_text"] = packet["summary"]
            return
        flags_version = int.from_bytes(body[0:2], "big")
        checksum_present = bool(flags_version & 0x8000)
        key_present = bool(flags_version & 0x2000)
        seq_present = bool(flags_version & 0x1000)
        proto_type = int.from_bytes(body[2:4], "big")
        offset = 4
        if checksum_present and len(body) >= offset + 4:
            offset += 4
        key = None
        if key_present and len(body) >= offset + 4:
            key = int.from_bytes(body[offset : offset + 4], "big")
            offset += 4
        if seq_present and len(body) >= offset + 4:
            offset += 4
        summary = f"GRE tunnel inner-proto 0x{proto_type:04x}"
        if key is not None:
            summary += f" key=0x{key:08x}"
        packet["summary"] = summary
        packet["banner_text"] = summary
        packet["payload_text"] = summary

    def _parse_esp(self, packet: dict, body: bytes, *, ip_version: int = 4):
        packet["proto"] = "esp"
        if len(body) < 8:
            packet["summary"] = "ESP packet"
            packet["banner_text"] = packet["summary"]
            return
        spi = int.from_bytes(body[0:4], "big")
        seq = int.from_bytes(body[4:8], "big")
        summary = f"ESP SPI=0x{spi:08x} seq={seq} (encrypted payload)"
        packet["summary"] = summary
        packet["banner_text"] = summary

    def _ah_header_length(self, length_field: int) -> int:
        # RFC 4302 §2.2: header length is expressed in 4-byte words, minus 2.
        return (length_field + 2) * 4

    def _parse_ah(self, packet: dict, body: bytes, *, ip_version: int = 4):
        if len(body) < 12:
            packet["proto"] = "ah"
            packet["summary"] = "AH packet"
            packet["banner_text"] = packet["summary"]
            return
        next_header = body[0]
        header_length = self._ah_header_length(body[1])
        spi = int.from_bytes(body[4:8], "big")
        seq = int.from_bytes(body[8:12], "big")
        inner = body[header_length:] if 0 < header_length <= len(body) else b""
        icmp_proto = IP_PROTO_ICMPV6 if ip_version == 6 else IP_PROTO_ICMP
        if next_header == IP_PROTO_TCP:
            self._parse_tcp(packet, inner, ip_version=ip_version)
        elif next_header == IP_PROTO_UDP:
            self._parse_udp(packet, inner, ip_version=ip_version)
        elif next_header == icmp_proto:
            self._parse_icmp(packet, inner, ipv6=(ip_version == 6))
        else:
            packet["proto"] = "ah"
            packet["summary"] = f"AH protocol {next_header}"
            packet["banner_text"] = packet["summary"]
        packet["summary"] = f"AH SPI=0x{spi:08x} seq={seq} | " + (packet.get("summary") or "")
        packet["banner_text"] = packet["summary"]

    def _parse_dhcp(self, packet: dict, payload: bytes):
        packet["proto"] = "dhcp"
        try:
            if len(payload) < 240 or payload[236:240] != b"\x63\x82\x53\x63":
                packet["summary"] = "DHCP/BOOTP packet"
                packet["banner_text"] = packet["summary"]
                return
            msg_type = None
            requested_ip = ""
            hostname = ""
            vendor_class = ""
            offset = 240
            while offset < len(payload):
                code = payload[offset]
                offset += 1
                if code == 0xFF:
                    break
                if code == 0x00:
                    continue
                if offset >= len(payload):
                    break
                length = payload[offset]
                offset += 1
                if offset + length > len(payload):
                    break
                value = payload[offset : offset + length]
                offset += length
                if code == 53 and len(value) == 1:
                    msg_type = value[0]
                elif code == 50 and len(value) == 4:
                    requested_ip = str(ipaddress.IPv4Address(value))
                elif code == 12:
                    hostname = value.decode("ascii", errors="replace")
                elif code == 60:
                    vendor_class = value.decode("ascii", errors="replace")
            type_name = DHCP_MSG_TYPES.get(msg_type, f"type {msg_type}" if msg_type is not None else "message")
            parts = [f"DHCP {type_name}"]
            if hostname:
                parts.append(f"host={hostname}")
            if requested_ip:
                parts.append(f"requested={requested_ip}")
            if vendor_class:
                parts.append(f"vendor={vendor_class}")
            summary = " ".join(parts)
            packet["summary"] = summary
            packet["banner_text"] = summary
            packet["payload_text"] = summary
        except Exception:
            packet["summary"] = packet.get("summary") or "DHCP/BOOTP packet"
            packet["banner_text"] = packet["summary"]

    def _parse_nbns(self, packet: dict, payload: bytes):
        packet["proto"] = "nbns"
        try:
            if len(payload) < 12:
                packet["summary"] = "NBNS packet"
                packet["banner_text"] = packet["summary"]
                return
            flags = int.from_bytes(payload[2:4], "big")
            is_response = bool(flags & 0x8000)
            qdcount = int.from_bytes(payload[4:6], "big")
            name = ""
            offset = 12
            if qdcount >= 1 and len(payload) >= offset + 1:
                length = payload[offset]
                if length == 32 and len(payload) >= offset + 1 + 32:
                    name = decode_nbns_name(payload[offset + 1 : offset + 33])
            summary = f"NBNS {'response' if is_response else 'query'}"
            if name:
                summary += f" for {name}"
            packet["summary"] = summary
            packet["banner_text"] = summary
            packet["payload_text"] = summary
        except Exception:
            packet["summary"] = packet.get("summary") or "NBNS packet"
            packet["banner_text"] = packet["summary"]

    def _apply_dns_result(self, packet: dict, payload: bytes, *, prefix: str, source: str):
        parsed = parse_dns_message(payload)
        if parsed.get("questions"):
            packet["domain"] = parsed["questions"][0]["name"]
            packet["domain_source"] = source
        summary = _dns_message_summary(prefix, parsed)
        if summary:
            packet["summary"] = summary
            packet["banner_text"] = summary
            if not packet.get("payload_text"):
                packet["payload_text"] = summary

    def _interpret_payload(self, packet: dict, payload: bytes) -> str:
        if not payload:
            return ""
        text = bytes_to_text_preview(payload)
        if is_printable_payload(payload):
            if text:
                packet["state"] = "open"
        if text:
            return text
        return ""

    def _classify_tcp_banner(self, packet: dict, payload: bytes) -> str:
        src_port = safe_int(packet.get("src_port"), 0)
        dst_port = safe_int(packet.get("dst_port"), 0)
        text = bytes_to_text_preview(payload)
        if payload.startswith(b"\x16\x03"):
            return "TLS handshake"
        if text.startswith("HTTP/1."):
            return "HTTP response"
        if text.startswith("GET ") or text.startswith("POST ") or text.startswith("HEAD "):
            return "HTTP request"
        if src_port == 22 or dst_port == 22:
            return "SSH session"
        if src_port == 25 or dst_port == 25:
            return "SMTP session"
        if src_port == 445 or dst_port == 445:
            return "SMB session"
        if src_port == 3389 or dst_port == 3389:
            return "RDP session"
        return text

    def _classify_udp_banner(self, packet: dict, payload: bytes) -> str:
        src_port = safe_int(packet.get("src_port"), 0)
        dst_port = safe_int(packet.get("dst_port"), 0)
        text = bytes_to_text_preview(payload)
        if src_port == 53 or dst_port == 53:
            return "DNS message"
        if src_port == 67 or dst_port == 67 or src_port == 68 or dst_port == 68:
            return "DHCP message"
        if src_port == 123 or dst_port == 123:
            return "NTP message"
        if src_port == 5353 or dst_port == 5353:
            return "mDNS message"
        return text

    def _classify_icmp_banner(self, packet: dict) -> str:
        type_code = (safe_int(packet.get("icmp_type"), 0), safe_int(packet.get("icmp_code"), 0))
        if type_code == (8, 0):
            return "ICMP echo request"
        if type_code == (0, 0):
            return "ICMP echo reply"
        return ""

    def _build_packet_from_sample(self, sample: dict, *, interface: str) -> dict:
        now = utc_now()
        proto = normalize_protocol_name(sample.get("proto"))
        src_ip = str(sample.get("src_ip") or "10.0.0.1").strip()
        dst_ip = str(sample.get("dst_ip") or "10.0.0.2").strip()
        src_port = safe_int(sample.get("src_port", 0), 0)
        dst_port = safe_int(sample.get("dst_port", 0), 0)
        payload_text = str(sample.get("payload_text") or "").strip()
        payload_bytes = payload_text.encode("utf-8", errors="ignore")
        packet = {
            "session_id": 0,
            "interface": interface,
            "eth_src": "aa:bb:cc:dd:ee:01",
            "eth_dst": "aa:bb:cc:dd:ee:02",
            "eth_type": ETHERTYPE_IPV4,
            "ip_version": 4,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "proto": proto,
            "src_port": src_port,
            "dst_port": dst_port,
            "ttl": 64,
            "hop_limit": 0,
            "length": 64 + len(payload_bytes),
            "payload_len": len(payload_bytes),
            "state": "open" if payload_bytes else "filtered",
            "scan_state": "active",
            "tcp_flags": "PSH,ACK" if proto == "tcp" else "",
            "icmp_type": 0 if proto == "icmp" else 0,
            "icmp_code": 0,
            "arp_opcode": 0,
            "summary": str(sample.get("summary") or ""),
            "payload_text": payload_text,
            "payload_hex": payload_bytes.hex(),
            "banner_text": str(sample.get("banner_text") or payload_text or ""),
            "direction": "unknown",
            "raw_packet": payload_bytes,
            "created_at": now,
            "updated_at": now,
        }
        packet["flow_key"] = stable_flow_key(proto, src_ip, src_port, dst_ip, dst_port)
        packet["direction"] = self._direction_for(packet)
        if not packet["summary"]:
            packet["summary"] = self._fallback_summary(packet)
        return packet
