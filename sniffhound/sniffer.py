from __future__ import annotations

import ipaddress
import math
import socket
import threading
import time
from dataclasses import dataclass, field

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
IP_PROTO_ICMP = 1
IP_PROTO_ICMPV6 = 58
SOL_PACKET = 263
PACKET_ADD_MEMBERSHIP = 1
PACKET_MR_PROMISC = 1
ETH_P_ALL = 0x0003


@dataclass
class CaptureState:
    running: bool = False
    interfaces: list[str] = field(default_factory=list)
    errors: dict[str, str] = field(default_factory=dict)
    packets_seen: int = 0
    packets_total_bytes: int = 0
    started_at: str = ""
    last_packet_at: str = ""


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
                "started_at": self.state.started_at,
                "last_packet_at": self.state.last_packet_at,
                "active_threads": active_threads,
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

    def _set_error(self, interface: str, message: str):
        with self._state_lock:
            self.state.errors[str(interface)] = str(message)

    def _touch_packet(self, packet: dict):
        payload_len = safe_int(packet.get("payload_len", 0), 0)
        length = safe_int(packet.get("length", 0), 0)
        with self._state_lock:
            self.state.packets_seen += 1
            self.state.packets_total_bytes += max(length, payload_len)
            self.state.last_packet_at = utc_now()

    def _broadcast_packet(self, packet: dict):
        event = {
            "type": "packet",
            "packet": packet,
            "generated_at": utc_now(),
        }
        self.hub.broadcast(event)
        self.hub.broadcast(
            {
                "type": "stats_update",
                "stats": {
                    "packets_seen": self.state.packets_seen,
                    "packets_total_bytes": self.state.packets_total_bytes,
                },
                "generated_at": utc_now(),
            }
        )

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
            self._store_packet(packet)

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
        rulesets = self.store.list_rulesets()
        matches = classify_packet(packet, rulesets)
        tags = self._build_packet_tags(packet, matches)
        packet["rule_hits"] = matches
        packet["tags"] = tags
        packet["banner_text"] = packet.get("banner_text") or packet.get("summary") or packet.get("payload_text") or ""
        saved = self.store.register_packet(packet)
        self._touch_packet(saved or packet)
        self._broadcast_packet(saved or packet)
        if self.state.packets_seen % 50 == 0:
            self.store.trim_oversized_tables()

    def _build_packet_tags(self, packet: dict, matches: list[dict]) -> list[dict]:
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
            "raw_packet": data[:],
            "created_at": now,
            "updated_at": now,
        }

    def _finalize_packet(self, packet: dict) -> dict:
        packet["flow_key"] = stable_flow_key(
            packet.get("proto") or "unknown",
            packet.get("src_ip") or packet.get("eth_src") or "unknown",
            packet.get("src_port") or 0,
            packet.get("dst_ip") or packet.get("eth_dst") or "unknown",
            packet.get("dst_port") or 0,
        )
        packet["direction"] = self._direction_for(packet)
        packet["banner_text"] = packet.get("banner_text") or packet.get("summary") or packet.get("payload_text") or ""
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
        elif proto == IP_PROTO_ICMP:
            self._parse_icmp(packet, body)
        else:
            packet["proto"] = f"ip{proto}"
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
        next_header = payload[6]
        packet["hop_limit"] = payload[7]
        packet["src_ip"] = str(ipaddress.IPv6Address(payload[8:24]))
        packet["dst_ip"] = str(ipaddress.IPv6Address(payload[24:40]))
        body = payload[40:]
        if next_header == IP_PROTO_TCP:
            self._parse_tcp(packet, body, ip_version=6)
        elif next_header == IP_PROTO_UDP:
            self._parse_udp(packet, body, ip_version=6)
        elif next_header in {IP_PROTO_ICMPV6}:
            self._parse_icmp(packet, body, ipv6=True)
        else:
            packet["proto"] = f"ip6-{next_header}"
            packet["summary"] = f"IPv6 protocol {next_header} {packet['src_ip']} → {packet['dst_ip']}"
            packet["payload_text"] = bytes_to_text_preview(body)
            packet["banner_text"] = packet["payload_text"]
        if not packet.get("summary"):
            packet["summary"] = self._fallback_summary(packet)

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
        packet["payload_text"] = self._interpret_payload(packet, payload)
        packet["banner_text"] = packet["payload_text"] or self._classify_tcp_banner(packet, payload)
        packet["summary"] = packet["banner_text"] or f"TCP {packet['src_ip']}:{packet['src_port']} → {packet['dst_ip']}:{packet['dst_port']}"
        if ip_version == 6 and not packet.get("hop_limit"):
            packet["hop_limit"] = 64
        if len(payload) >= 1 and payload[:1] == b"\x16":
            packet["banner_text"] = packet["banner_text"] or "TLS handshake"

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
            "banner_text": str(sample.get("summary") or payload_text or ""),
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
