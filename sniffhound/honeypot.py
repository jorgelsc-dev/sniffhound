from __future__ import annotations

import logging
import queue
import socket
import sqlite3
import ssl
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

from .utils import (
    bytes_to_hex_preview,
    bytes_to_text_preview,
    normalize_protocol_name,
    normalize_text,
    safe_int,
    utc_now,
)


LOG_MAX_BYTES = 10 * 1024 * 1024
LOG_BACKUP_COUNT = 5
LOG_FILE = Path("honeypot.log")
EVENT_DB_FILE = Path("honeypot_events.db")
CERT_FILE = Path("honeypot_cert.pem")
KEY_FILE = Path("honeypot_key.pem")

BIND_HOST = "0.0.0.0"
READ_TIMEOUT_SECONDS = 6
MAX_PACKET_SIZE = 4096
MAX_HTTP_REQUEST_SIZE = 16384
MAX_COMMAND_ROUNDS = 20
DB_BATCH_SIZE = 100

HTTP_TCP_PORTS = {80, 8000, 8080, 8888, 9200}
HTTPS_TCP_PORTS = {443, 8443, 9443}
FTP_PORTS = {21, 2121}
FTPS_PORTS = {990}
SMTP_PORTS = {25, 587, 2525}
SMTPS_PORTS = {465}
POP3_PORTS = {110}
POP3S_PORTS = {995}
IMAP_PORTS = {143}
IMAPS_PORTS = {993}
TELNET_PORTS = {23}
SSH_PORTS = {22}
MYSQL_PORTS = {3306}
POSTGRES_PORTS = {5432}
LDAP_PORTS = {389}
LDAPS_PORTS = {636}
REDIS_PORTS = {6379}
MEMCACHED_TCP_PORTS = {11211}
VNC_PORTS = {5900}
RDP_PORTS = {3389}
SMB_PORTS = {139, 445}
DNS_TCP_PORTS = {53}
MONGODB_PORTS = {27017}
MQTT_PORTS = {1883}
MQTTS_PORTS = {8883}
AMQP_PORTS = {5672}
AMQPS_PORTS = {5671}
RTSP_PORTS = {554}
GENERIC_TCP_PORTS = {2049}

TLS_TCP_PORTS = (
    HTTPS_TCP_PORTS
    | FTPS_PORTS
    | SMTPS_PORTS
    | POP3S_PORTS
    | IMAPS_PORTS
    | LDAPS_PORTS
    | MQTTS_PORTS
    | AMQPS_PORTS
)

DNS_UDP_PORTS = {53}
DHCP_UDP_PORTS = {67, 68}
TFTP_UDP_PORTS = {69}
NTP_UDP_PORTS = {123}
NETBIOS_UDP_PORTS = {137, 138}
SNMP_UDP_PORTS = {161}
IPSEC_UDP_PORTS = {500, 4500}
SYSLOG_UDP_PORTS = {514}
RIP_UDP_PORTS = {520}
RADIUS_UDP_PORTS = {1812, 1813}
SSDP_UDP_PORTS = {1900}
SIP_UDP_PORTS = {5060}
MDNS_UDP_PORTS = {5353}
MEMCACHED_UDP_PORTS = {11211}

COMMON_PORTS = {
    "tcp": sorted(
        HTTP_TCP_PORTS
        | HTTPS_TCP_PORTS
        | FTP_PORTS
        | FTPS_PORTS
        | SMTP_PORTS
        | SMTPS_PORTS
        | POP3_PORTS
        | POP3S_PORTS
        | IMAP_PORTS
        | IMAPS_PORTS
        | TELNET_PORTS
        | SSH_PORTS
        | MYSQL_PORTS
        | POSTGRES_PORTS
        | LDAP_PORTS
        | LDAPS_PORTS
        | REDIS_PORTS
        | MEMCACHED_TCP_PORTS
        | VNC_PORTS
        | RDP_PORTS
        | SMB_PORTS
        | DNS_TCP_PORTS
        | MONGODB_PORTS
        | MQTT_PORTS
        | MQTTS_PORTS
        | AMQP_PORTS
        | AMQPS_PORTS
        | RTSP_PORTS
        | GENERIC_TCP_PORTS
    ),
    "udp": sorted(
        DNS_UDP_PORTS
        | DHCP_UDP_PORTS
        | TFTP_UDP_PORTS
        | NTP_UDP_PORTS
        | NETBIOS_UDP_PORTS
        | SNMP_UDP_PORTS
        | IPSEC_UDP_PORTS
        | SYSLOG_UDP_PORTS
        | RIP_UDP_PORTS
        | RADIUS_UDP_PORTS
        | SSDP_UDP_PORTS
        | SIP_UDP_PORTS
        | MDNS_UDP_PORTS
        | MEMCACHED_UDP_PORTS
    ),
}

FAVICON_ICO = bytes.fromhex(
    "00000100010001010000010020003000000016000000"
    "280000000100000002000000010020000000000008000000"
    "130B0000130B000000000000000000000000FFFF000000000000"
)

TCP_BANNERS: dict[int, str | bytes] = {
    21: "220 ProFTPD 1.3.5 Server (Honeypot)\r\n",
    22: "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3\r\n",
    23: "Debian GNU/Linux 12 honeypot ttyS0\r\nlogin: ",
    25: "220 smtp.honeypot.local ESMTP Postfix\r\n",
    53: "DNS over TCP Honeypot Ready\r\n",
    110: "+OK POP3 Honeypot Server Ready\r\n",
    139: b"\x00\x00\x00\x85\xffSMBr\x00\x00\x00\x00\x18\x01\x28\x00",
    143: "* OK IMAP4rev1 Honeypot Service Ready\r\n",
    389: "LDAP Honeypot Service Ready\r\n",
    445: b"\x00\x00\x00\x90\xffSMBr\x00\x00\x00\x00\x18\x53\xc8",
    554: "RTSP/1.0 200 OK\r\nServer: Live555-Honeypot\r\n\r\n",
    587: "220 smtp.honeypot.local ESMTP Submission Ready\r\n",
    990: "220 FTPS Honeypot Service Ready\r\n",
    993: "* OK IMAP4rev1 Honeypot over TLS Ready\r\n",
    995: "+OK POP3 Honeypot over TLS Ready\r\n",
    2049: "NFS server honeypot ready\r\n",
    2121: "220 FTP Honeypot Ready\r\n",
    3306: b"\x19\x00\x00\x00\x0a8.0.30-honeypot\x00\x01\x00\x00\x00abcdefgh\x00",
    3389: b"\x03\x00\x00\x13\x0e\xd0\x00\x00\x124\x00\x02\x00\x08\x00\x02\x00\x00\x00",
    5432: "POSTGRES 13.0 Honeypot\r\n",
    5671: b"AMQP\x00\x00\x09\x01",
    5672: b"AMQP\x00\x00\x09\x01",
    5900: b"RFB 003.008\n",
    6379: b"-NOAUTH Authentication required.\r\n",
    8000: "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0\r\n\r\n",
    8080: "HTTP/1.1 200 OK\r\nServer: Apache/2.4.46 (Honeypot)\r\n\r\n",
    8888: "HTTP/1.1 200 OK\r\nServer: Caddy/2.7.0\r\n\r\n",
    9200: "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\r\n",
    9443: "HTTP/1.1 200 OK\r\nServer: nginx/1.18.0 (TLS)\r\n\r\n",
    11211: "STAT pid 2134\r\nEND\r\n",
    27017: "It looks like you are trying to access MongoDB over HTTP on the native driver port.\n",
}

UDP_BANNERS: dict[int, str | bytes] = {
    53: b"\x00\x00\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00",
    67: "DHCP Honeypot Service",
    68: "DHCP Client Honeypot",
    69: "TFTP Honeypot",
    123: "NTPv4 Server (Honeypot)",
    137: "NetBIOS Name Service Honeypot",
    138: "NetBIOS Datagram Service Honeypot",
    161: "public\nHoneypot SNMPv1 Server",
    500: "ISAKMP Honeypot Response",
    514: "<13>honeypot syslog ack",
    520: "RIP Honeypot Response",
    1812: "RADIUS Access-Reject (Honeypot)",
    1813: "RADIUS Accounting-Response (Honeypot)",
    4500: "IKEv2 Honeypot Response",
    1900: "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nSERVER: UPnP/1.0 Honeypot\r\n\r\n",
    5060: "SIP/2.0 200 OK\r\nServer: Asterisk PBX Honeypot\r\n\r\n",
    5353: b"\x00\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00",
    11211: "STAT version 1.6.9\r\nEND\r\n",
}


def _build_logger() -> logging.Logger:
    logger = logging.getLogger("sniffhound.honeypot")
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    handler = RotatingFileHandler(
        LOG_FILE,
        maxBytes=LOG_MAX_BYTES,
        backupCount=LOG_BACKUP_COUNT,
        encoding="utf-8",
    )
    handler.setFormatter(logging.Formatter("%(asctime)s - %(message)s"))
    logger.addHandler(handler)
    logger.propagate = False
    return logger


LOGGER = _build_logger()


def _normalize_payload(data):
    if data is None:
        return b""
    if isinstance(data, (bytes, bytearray)):
        return bytes(data)
    return str(data).encode("utf-8", errors="replace")


def _safe_send(sock, payload):
    if payload is None:
        return
    try:
        sock.sendall(payload if isinstance(payload, (bytes, bytearray)) else str(payload).encode("utf-8", errors="replace"))
    except Exception:
        pass


def _recv_line(sock, max_len: int = MAX_PACKET_SIZE) -> bytes:
    data = b""
    while len(data) < max_len:
        try:
            chunk = sock.recv(1)
        except socket.timeout:
            break
        if not chunk:
            break
        data += chunk
        if data.endswith(b"\n"):
            break
    return data


def _decode_line(data: bytes) -> str:
    return data.decode("utf-8", errors="replace").strip()


def _read_http_request(sock) -> bytes:
    sock.settimeout(READ_TIMEOUT_SECONDS)
    data = b""
    while b"\r\n\r\n" not in data and len(data) < MAX_HTTP_REQUEST_SIZE:
        chunk = sock.recv(MAX_PACKET_SIZE)
        if not chunk:
            break
        data += chunk
    return data


def _build_http_response(status_code: int, reason: str, body: bytes, content_type: str) -> bytes:
    headers = [
        f"HTTP/1.1 {status_code} {reason}",
        "Server: nginx/1.18.0",
        f"Date: {utc_now()}",
        f"Content-Type: {content_type}",
        f"Content-Length: {len(body)}",
        "Connection: close",
    ]
    return ("\r\n".join(headers) + "\r\n\r\n").encode("utf-8") + body


def _normalize_dns_response_ip(response_ip: str) -> bytes:
    try:
        return socket.inet_aton(response_ip)
    except OSError:
        return socket.inet_aton("127.0.0.1")


def _decode_dns_name(packet: bytes, start_idx: int):
    labels = []
    idx = start_idx
    next_idx = start_idx
    jumped = False
    jumps = 0

    while idx < len(packet):
        length = packet[idx]
        if length == 0:
            idx += 1
            if not jumped:
                next_idx = idx
            break
        if (length & 0xC0) == 0xC0:
            if idx + 1 >= len(packet):
                raise ValueError("Nombre DNS comprimido truncado")
            pointer = ((length & 0x3F) << 8) | packet[idx + 1]
            if pointer >= len(packet):
                raise ValueError("Puntero DNS fuera de rango")
            if not jumped:
                next_idx = idx + 2
            idx = pointer
            jumped = True
            jumps += 1
            if jumps > 20:
                raise ValueError("Demasiados saltos en nombre DNS")
            continue
        if length > 63:
            raise ValueError("Etiqueta DNS invalida")
        idx += 1
        if idx + length > len(packet):
            raise ValueError("Etiqueta DNS truncada")
        labels.append(packet[idx : idx + length].decode("utf-8", errors="replace"))
        idx += length
    else:
        raise ValueError("Nombre DNS sin terminador")

    return (".".join(labels) if labels else "."), next_idx


def _parse_dns_questions(query: bytes):
    if len(query) < 12:
        return []

    qdcount = int.from_bytes(query[4:6], "big")
    idx = 12
    questions = []
    for _ in range(qdcount):
        if idx >= len(query):
            break
        name_offset = idx
        try:
            domain, name_end = _decode_dns_name(query, idx)
        except ValueError:
            break
        if name_end + 4 > len(query):
            break
        qtype = int.from_bytes(query[name_end : name_end + 2], "big")
        qclass = int.from_bytes(query[name_end + 2 : name_end + 4], "big")
        question_end = name_end + 4
        questions.append(
            {
                "domain": domain,
                "qtype": qtype,
                "qclass": qclass,
                "name_offset": name_offset,
                "wire": query[idx:question_end],
            }
        )
        idx = question_end
    return questions


def _build_dns_response(query: bytes, response_ip: str):
    if len(query) < 12:
        return UDP_BANNERS[53], []

    transaction_id = query[:2]
    questions = _parse_dns_questions(query)
    if not questions:
        empty_header = transaction_id + b"\x81\x82" + b"\x00\x00\x00\x00\x00\x00\x00\x00"
        return empty_header, []

    question_section = b"".join(question["wire"] for question in questions)
    ip_bytes = _normalize_dns_response_ip(response_ip)

    answers = []
    for question in questions:
        name_ptr = (0xC000 | question["name_offset"]).to_bytes(2, "big")
        answer = name_ptr + b"\x00\x01\x00\x01" + (60).to_bytes(4, "big") + b"\x00\x04" + ip_bytes
        answers.append(answer)

    header = (
        transaction_id
        + b"\x81\x80"
        + len(questions).to_bytes(2, "big")
        + len(answers).to_bytes(2, "big")
        + b"\x00\x00\x00\x00"
    )
    return header + question_section + b"".join(answers), questions


def _build_ntp_response(request_data: bytes) -> bytes:
    response = bytearray(48)
    response[0] = 0x24
    response[1] = 1
    response[2] = 6
    response[3] = 0xEC

    ntp_epoch = datetime(1900, 1, 1, tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    seconds_since_ntp = int((now - ntp_epoch).total_seconds())
    timestamp = seconds_since_ntp.to_bytes(4, "big", signed=False) + b"\x00\x00\x00\x00"

    if len(request_data) >= 48:
        response[24:32] = request_data[40:48]
    response[32:40] = timestamp
    response[40:48] = timestamp
    return bytes(response)


def _build_sip_response(request_data: bytes, addr):
    text = request_data.decode("utf-8", errors="replace")
    headers = {}
    for line in text.split("\r\n")[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip().lower()] = value.strip()

    via = headers.get("via", f"SIP/2.0/UDP {addr[0]}:{addr[1]};branch=z9hG4bK-honeypot")
    from_h = headers.get("from", "<sip:scanner@honeypot.local>")
    to_h = headers.get("to", "<sip:service@honeypot.local>")
    call_id = headers.get("call-id", "honeypot-call")
    cseq = headers.get("cseq", "1 OPTIONS")

    return (
        "SIP/2.0 200 OK\r\n"
        f"Via: {via}\r\n"
        f"From: {from_h}\r\n"
        f"To: {to_h};tag=hp1234\r\n"
        f"Call-ID: {call_id}\r\n"
        f"CSeq: {cseq}\r\n"
        "Server: Asterisk PBX Honeypot\r\n"
        "Content-Length: 0\r\n\r\n"
    ).encode("utf-8")


def _build_rtsp_response(request_text: str) -> bytes:
    cseq = "1"
    for line in request_text.split("\r\n"):
        if line.lower().startswith("cseq:"):
            cseq = line.split(":", 1)[1].strip()
            break

    return (
        "RTSP/1.0 200 OK\r\n"
        f"CSeq: {cseq}\r\n"
        "Server: Live555-Honeypot\r\n"
        "Public: OPTIONS, DESCRIBE, SETUP, TEARDOWN, PLAY, PAUSE\r\n"
        "Content-Length: 0\r\n\r\n"
    ).encode("utf-8")


def _build_ldap_bind_response(request_data: bytes) -> bytes:
    message_id = 1
    if len(request_data) >= 5 and request_data[0] == 0x30 and request_data[2] == 0x02 and request_data[3] == 0x01:
        message_id = request_data[4]
    return bytes([0x30, 0x0C, 0x02, 0x01, message_id, 0x61, 0x07, 0x0A, 0x01, 0x31, 0x04, 0x00, 0x04, 0x00])


def _build_postgres_error_packet() -> bytes:
    payload = b"SERROR\x00C28000\x00Mpassword authentication failed\x00\x00"
    error_response = b"E" + (len(payload) + 4).to_bytes(4, "big") + payload
    ready_for_query = b"Z\x00\x00\x00\x05I"
    return error_response + ready_for_query


@dataclass
class HoneypotState:
    running: bool = False
    errors: dict[str, str] = field(default_factory=dict)
    listeners: list[str] = field(default_factory=list)
    packets_seen: int = 0
    packets_total_bytes: int = 0
    started_at: str = ""
    last_event_at: str = ""
    session_id: int = 0


class HoneypotEngine:
    def __init__(self, store, hub, *, bind_host: str = BIND_HOST):
        self.store = store
        self.hub = hub
        self.bind_host = bind_host
        self._stop_event = threading.Event()
        self._state_lock = threading.RLock()
        self._event_queue: queue.Queue[dict[str, Any]] = queue.Queue()
        self._threads: list[threading.Thread] = []
        self._writer_thread: threading.Thread | None = None
        self._state = HoneypotState()
        self._tls_sni_map: dict[int, str] = {}
        self._tls_sni_lock = threading.Lock()
        self._event_db: sqlite3.Connection | None = None
        self._tls_context: ssl.SSLContext | None = None

    def _set_error(self, name: str, message: str):
        with self._state_lock:
            self._state.errors[str(name)] = str(message)

    def _touch_packet(self, packet: dict):
        payload_len = safe_int(packet.get("payload_len", 0), 0)
        length = safe_int(packet.get("length", 0), 0)
        with self._state_lock:
            self._state.packets_seen += 1
            self._state.packets_total_bytes += max(length, payload_len)
            self._state.last_event_at = utc_now()

    def _session_id(self) -> int:
        with self._state_lock:
            if self._state.session_id > 0 and self.store.get_session(self._state.session_id):
                return self._state.session_id

        existing = safe_int(self.store.get_runtime_config("honeypot_session_id", "0"), 0)
        if existing and self.store.get_session(existing):
            with self._state_lock:
                self._state.session_id = existing
            return existing

        row = self.store.create_session(
            {
                "network": "0.0.0.0/0",
                "type": "honeypot",
                "proto": "all",
                "port_mode": "preset",
                "port_start": 0,
                "port_end": 0,
                "status": "active",
                "timesleep": 0.5,
                "progress": 0.0,
                "interface": "honeypot",
                "filter_text": "honeypot mode",
            }
        )
        session_id = safe_int(row.get("id"), 0)
        if session_id:
            self.store.set_runtime_config("honeypot_session_id", str(session_id))
        with self._state_lock:
            self._state.session_id = session_id
        return session_id

    def _ensure_event_db(self):
        if self._event_db is not None:
            return self._event_db
        conn = sqlite3.connect(EVENT_DB_FILE, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS connection_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_time TEXT NOT NULL,
                protocol TEXT NOT NULL,
                dst_port INTEGER NOT NULL,
                src_ip TEXT NOT NULL,
                src_port INTEGER NOT NULL,
                data_len INTEGER NOT NULL,
                data_preview TEXT,
                data BLOB
            );
            CREATE INDEX IF NOT EXISTS idx_connection_events_time ON connection_events(event_time);
            CREATE INDEX IF NOT EXISTS idx_connection_events_protocol ON connection_events(protocol);
            CREATE INDEX IF NOT EXISTS idx_connection_events_src ON connection_events(src_ip, src_port);
            CREATE INDEX IF NOT EXISTS idx_connection_events_dst_port ON connection_events(dst_port);

            CREATE TABLE IF NOT EXISTS tls_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_time TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                src_port INTEGER NOT NULL,
                dst_port INTEGER NOT NULL,
                tls_version TEXT,
                cipher_name TEXT,
                cipher_protocol TEXT,
                cipher_bits INTEGER,
                alpn TEXT,
                sni TEXT,
                peer_cert BLOB
            );
            CREATE INDEX IF NOT EXISTS idx_tls_sessions_time ON tls_sessions(event_time);
            CREATE INDEX IF NOT EXISTS idx_tls_sessions_src ON tls_sessions(src_ip, src_port);
            CREATE INDEX IF NOT EXISTS idx_tls_sessions_dst_port ON tls_sessions(dst_port);

            CREATE TABLE IF NOT EXISTS dns_queries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_time TEXT NOT NULL,
                src_ip TEXT NOT NULL,
                src_port INTEGER NOT NULL,
                dst_port INTEGER NOT NULL,
                domain TEXT NOT NULL,
                query_type INTEGER NOT NULL,
                response_ip TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_dns_queries_time ON dns_queries(event_time);
            CREATE INDEX IF NOT EXISTS idx_dns_queries_domain ON dns_queries(domain);
            CREATE INDEX IF NOT EXISTS idx_dns_queries_src ON dns_queries(src_ip, src_port);
            """
        )
        self._event_db = conn
        return conn

    def _close_event_db(self):
        conn = self._event_db
        self._event_db = None
        if conn is None:
            return
        try:
            conn.close()
        except Exception:
            pass

    def _event_writer(self):
        conn = self._ensure_event_db()
        try:
            while not self._stop_event.is_set() or not self._event_queue.empty():
                try:
                    event = self._event_queue.get(timeout=0.5)
                except queue.Empty:
                    continue
                batch = [event]
                while len(batch) < DB_BATCH_SIZE:
                    try:
                        batch.append(self._event_queue.get_nowait())
                    except queue.Empty:
                        break

                try:
                    for item in batch:
                        packet = item.get("packet") if isinstance(item, dict) else None
                        meta = item.get("meta") if isinstance(item, dict) else {}
                        if not isinstance(packet, dict):
                            continue
                        self._insert_event_row(conn, packet, meta if isinstance(meta, dict) else {})
                        saved = self.store.register_packet(packet)
                        self._touch_packet(saved or packet)
                        self._broadcast_packet(saved or packet)
                except Exception:
                    LOGGER.exception("Error al guardar eventos honeypot")
                finally:
                    for _ in batch:
                        self._event_queue.task_done()
        finally:
            try:
                conn.commit()
            except Exception:
                pass

    def _insert_event_row(self, conn: sqlite3.Connection, packet: dict, meta: dict):
        payload = _normalize_payload(packet.get("raw_packet") or packet.get("payload_text") or b"")
        event_time = str(packet.get("created_at") or utc_now())
        proto = normalize_protocol_name(packet.get("proto"))
        src_ip = str(packet.get("src_ip") or "").strip()
        src_port = safe_int(packet.get("src_port", 0), 0)
        dst_port = safe_int(packet.get("dst_port", 0), 0)
        conn.execute(
            """
            INSERT INTO connection_events
            (event_time, protocol, dst_port, src_ip, src_port, data_len, data_preview, data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_time,
                proto,
                dst_port,
                src_ip,
                src_port,
                safe_int(packet.get("length") or len(payload), 0),
                bytes_to_hex_preview(payload),
                sqlite3.Binary(payload),
            ),
        )
        tls = meta.get("tls") if isinstance(meta, dict) else None
        if isinstance(tls, dict):
            peer_cert = tls.get("peer_cert") or b""
            if isinstance(peer_cert, str):
                peer_cert = peer_cert.encode("utf-8", errors="replace")
            conn.execute(
                """
                INSERT INTO tls_sessions
                (event_time, src_ip, src_port, dst_port, tls_version, cipher_name, cipher_protocol, cipher_bits, alpn, sni, peer_cert)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_time,
                    src_ip,
                    src_port,
                    dst_port,
                    str(tls.get("tls_version") or ""),
                    str(tls.get("cipher_name") or ""),
                    str(tls.get("cipher_protocol") or ""),
                    safe_int(tls.get("cipher_bits"), 0),
                    str(tls.get("alpn") or ""),
                    str(tls.get("sni") or ""),
                    sqlite3.Binary(bytes(peer_cert)),
                ),
            )
        dns = meta.get("dns") if isinstance(meta, dict) else None
        if isinstance(dns, dict):
            for question in dns.get("questions") or []:
                if not isinstance(question, dict):
                    continue
                conn.execute(
                    """
                    INSERT INTO dns_queries
                    (event_time, src_ip, src_port, dst_port, domain, query_type, response_ip)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event_time,
                        src_ip,
                        src_port,
                        dst_port,
                        str(question.get("domain") or ""),
                        safe_int(question.get("qtype"), 0),
                        str(dns.get("response_ip") or "127.0.0.1"),
                    ),
                )
        conn.commit()

    def _broadcast_packet(self, packet: dict):
        self.hub.broadcast({"type": "packet", "packet": packet, "generated_at": utc_now()})
        self.hub.broadcast(
            {
                "type": "stats_update",
                "stats": {
                    "packets_seen": self._state.packets_seen,
                    "packets_total_bytes": self._state.packets_total_bytes,
                    "mode": "honeypot",
                },
                "generated_at": utc_now(),
            }
        )

    def snapshot(self) -> dict:
        with self._state_lock:
            return {
                "running": bool(self._state.running),
                "mode": "honeypot",
                "errors": dict(self._state.errors),
                "listeners": list(self._state.listeners),
                "packets_seen": int(self._state.packets_seen),
                "packets_total_bytes": int(self._state.packets_total_bytes),
                "started_at": self._state.started_at,
                "last_event_at": self._state.last_event_at,
                "session_id": int(self._state.session_id),
                "active_threads": sum(1 for thread in self._threads if thread.is_alive()) + (1 if self._writer_thread and self._writer_thread.is_alive() else 0),
                "log_file": str(LOG_FILE),
                "event_db": str(EVENT_DB_FILE),
                "tls_ready": self._tls_context is not None,
            }

    def start(self):
        with self._state_lock:
            if self._state.running:
                return self.snapshot()
            self._stop_event.clear()
            self._state.running = True
            self._state.errors = {}
            self._state.listeners = [f"tcp/{port}" for port in COMMON_PORTS["tcp"]] + [f"udp/{port}" for port in COMMON_PORTS["udp"]]
            self._state.packets_seen = 0
            self._state.packets_total_bytes = 0
            self._state.started_at = utc_now()
            self._state.last_event_at = ""

        self._session_id()
        self._writer_thread = threading.Thread(target=self._event_writer, name="sniffhound-honeypot-writer", daemon=True)
        self._writer_thread.start()

        try:
            self._tls_context = self._create_tls_context()
            LOGGER.info("TLS habilitado con certificados %s y %s", CERT_FILE, KEY_FILE)
        except Exception as error:
            self._tls_context = None
            self._set_error("tls", str(error))
            LOGGER.exception("No se pudo inicializar TLS")

        threads: list[threading.Thread] = []
        for port in COMMON_PORTS["tcp"]:
            tls_context = self._tls_context if port in TLS_TCP_PORTS else None
            if port in TLS_TCP_PORTS and tls_context is None:
                self._set_error(f"tcp/{port}", "TLS context unavailable")
                continue
            thread = threading.Thread(
                target=self._tcp_listener,
                args=(port, tls_context),
                name=f"sniffhound-honeypot-tcp-{port}",
                daemon=True,
            )
            thread.start()
            threads.append(thread)

        for port in COMMON_PORTS["udp"]:
            thread = threading.Thread(
                target=self._udp_listener,
                args=(port,),
                name=f"sniffhound-honeypot-udp-{port}",
                daemon=True,
            )
            thread.start()
            threads.append(thread)

        self._threads = threads
        LOGGER.info("Honeypot activo en %s con %s listeners", self.bind_host, len(self._state.listeners))
        return self.snapshot()

    def stop(self):
        self._stop_event.set()
        with self._state_lock:
            self._state.running = False
        for thread in list(self._threads):
            if thread.is_alive():
                thread.join(timeout=0.8)
        if self._writer_thread and self._writer_thread.is_alive():
            self._writer_thread.join(timeout=1.2)
        self._threads = []
        self._writer_thread = None
        self._close_event_db()
        try:
            session_id = int(self._state.session_id or 0)
            if session_id:
                self.store.set_session_status(session_id, "stopped")
        except Exception:
            pass
        return self.snapshot()

    def restart(self):
        self.stop()
        return self.start()

    def _create_tls_context(self):
        if not CERT_FILE.is_file() or not KEY_FILE.is_file():
            raise FileNotFoundError(
                f"No se encontraron certificados TLS: {CERT_FILE} y/o {KEY_FILE}. "
                "Generalos con OpenSSL o copia un par PEM valido."
            )
        tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_context.minimum_version = ssl.TLSVersion.TLSv1_2
        tls_context.load_cert_chain(certfile=str(CERT_FILE), keyfile=str(KEY_FILE))
        tls_context.set_servername_callback(self._remember_tls_sni)
        return tls_context

    def _remember_tls_sni(self, ssl_sock, server_name, _ssl_context):
        if not server_name:
            return
        try:
            fileno = ssl_sock.fileno()
        except Exception:
            return
        with self._tls_sni_lock:
            self._tls_sni_map[fileno] = server_name

    def _capture_tls_session(self, addr, port: int, tls_sock):
        cipher = tls_sock.cipher() or ("", "", None)
        tls_version = tls_sock.version() or ""
        alpn = tls_sock.selected_alpn_protocol() or ""
        peer_cert = b""
        try:
            peer_cert = tls_sock.getpeercert(binary_form=True) or b""
        except Exception:
            peer_cert = b""

        sni = ""
        try:
            fileno = tls_sock.fileno()
            with self._tls_sni_lock:
                sni = self._tls_sni_map.pop(fileno, "") or ""
        except Exception:
            sni = ""

        summary = (
            f"TLS session version={tls_version or '-'} "
            f"cipher={cipher[0] if len(cipher) > 0 else '-'} "
            f"protocol={cipher[1] if len(cipher) > 1 else '-'} "
            f"bits={cipher[2] if len(cipher) > 2 else '-'} "
            f"sni={sni or '-'} alpn={alpn or '-'}"
        )
        LOGGER.info("%s:%s -> %s", addr[0], addr[1], summary)
        return {
            "tls_version": tls_version,
            "cipher_name": cipher[0] if len(cipher) > 0 else "",
            "cipher_protocol": cipher[1] if len(cipher) > 1 else "",
            "cipher_bits": cipher[2] if len(cipher) > 2 else None,
            "alpn": alpn,
            "sni": sni,
            "peer_cert": peer_cert,
            "summary": summary,
        }

    def _socket_listener_ip(self, sock, peer_ip: str) -> str:
        try:
            local_ip = sock.getsockname()[0]
            if local_ip and local_ip != "0.0.0.0":
                return local_ip
        except Exception:
            pass
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe_sock:
                probe_sock.connect((peer_ip, 53))
                local_ip = probe_sock.getsockname()[0]
                if local_ip:
                    return local_ip
        except Exception:
            pass
        return "127.0.0.1"

    def _build_packet(
        self,
        *,
        protocol: str,
        port: int,
        addr,
        data=None,
        banner_text: str = "",
        summary: str = "",
        meta: dict[str, Any] | None = None,
    ) -> dict:
        payload = _normalize_payload(data)
        payload_text = bytes_to_text_preview(payload, limit=400)
        listener_ip = self.bind_host if self.bind_host not in {"0.0.0.0", "::"} else "127.0.0.1"
        packet = {
            "session_id": self._session_id(),
            "interface": f"honeypot:{port}",
            "direction": "inbound",
            "eth_src": "",
            "eth_dst": "",
            "eth_type": 0,
            "ip_version": 4,
            "src_ip": addr[0],
            "dst_ip": listener_ip,
            "proto": normalize_protocol_name(protocol),
            "src_port": addr[1],
            "dst_port": port,
            "ttl": 64,
            "hop_limit": 0,
            "length": len(payload),
            "payload_len": len(payload),
            "state": "open",
            "scan_state": "active",
            "tcp_flags": "",
            "icmp_type": 0,
            "icmp_code": 0,
            "arp_opcode": 0,
            "summary": normalize_text(summary or banner_text or f"{protocol.upper()} honeypot", limit=400),
            "payload_text": normalize_text(payload_text, limit=400),
            "payload_hex": bytes_to_hex_preview(payload),
            "banner_text": normalize_text(banner_text or summary or payload_text, limit=400),
            "tags": [
                {"key": "mode", "value": "honeypot"},
                {"key": "service", "value": normalize_protocol_name(protocol)},
                {"key": "port", "value": str(port)},
            ],
            "rule_hits": [
                {"rule_id": "honeypot", "rule_name": "Honeypot", "tag": "honeypot", "label": "Honeypot", "severity": "high"}
            ],
            "raw_packet": payload,
            "created_at": utc_now(),
            "updated_at": utc_now(),
        }
        if meta:
            packet["honeypot_meta"] = meta
            if meta.get("tls"):
                packet["tags"].append({"key": "tls", "value": "enabled"})
            if meta.get("sni"):
                packet["tags"].append({"key": "sni", "value": str(meta.get("sni"))})
        return packet

    def _emit_packet(self, packet: dict):
        self._event_queue.put({"packet": packet, "meta": packet.get("honeypot_meta") or {}})

    def _listen(self, port: int, handler, *, udp: bool = False):
        sock_type = socket.SOCK_DGRAM if udp else socket.SOCK_STREAM
        with socket.socket(socket.AF_INET, sock_type) as sock:
            self._last_socket = sock
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind((self.bind_host, port))
            except Exception as error:
                self._set_error(f"{'udp' if udp else 'tcp'}/{port}", f"bind failed: {error}")
                LOGGER.exception("No se pudo enlazar puerto %s", port)
                return

            if not udp:
                sock.listen(20)
                sock.settimeout(1.0)
                LOGGER.info("TCP honeypot activo en %s:%s", self.bind_host, port)
                while not self._stop_event.is_set():
                    try:
                        client, addr = sock.accept()
                    except socket.timeout:
                        continue
                    except OSError as error:
                        if self._stop_event.is_set():
                            break
                        self._set_error(f"tcp/{port}", str(error))
                        continue
                    threading.Thread(target=handler, args=(client, addr, port), daemon=True).start()
            else:
                sock.settimeout(1.0)
                LOGGER.info("UDP honeypot activo en %s:%s", self.bind_host, port)
                while not self._stop_event.is_set():
                    try:
                        data, addr = sock.recvfrom(MAX_PACKET_SIZE)
                    except socket.timeout:
                        continue
                    except OSError as error:
                        if self._stop_event.is_set():
                            break
                        self._set_error(f"udp/{port}", str(error))
                        continue
                    if data:
                        handler(sock, addr, port, data)

    def _tcp_listener(self, port: int, tls_context=None):
        if tls_context is not None:
            self._listen(port, lambda client, addr, p: self._handle_tcp(client, addr, p, tls_context=tls_context))
        else:
            self._listen(port, self._handle_tcp)

    def _udp_listener(self, port: int):
        self._listen(port, self._handle_udp, udp=True)

    def _handle_tcp(self, client_sock, addr, port, tls_context=None):
        wrapped_sock = client_sock
        meta: dict[str, Any] = {}
        use_tls = tls_context is not None
        try:
            if use_tls:
                wrapped_sock = tls_context.wrap_socket(client_sock, server_side=True)
                meta["tls"] = self._capture_tls_session(addr, port, wrapped_sock)

            if port in HTTP_TCP_PORTS or port in HTTPS_TCP_PORTS:
                self._handle_http_service(wrapped_sock, addr, port, use_tls=use_tls, meta=meta)
            elif port in FTP_PORTS or port in FTPS_PORTS:
                self._handle_ftp_service(wrapped_sock, addr, port, use_tls=use_tls, meta=meta)
            elif port in SMTP_PORTS or port in SMTPS_PORTS:
                self._handle_smtp_service(wrapped_sock, addr, port, use_tls=use_tls, meta=meta)
            elif port in POP3_PORTS or port in POP3S_PORTS:
                self._handle_pop3_service(wrapped_sock, addr, port, use_tls=use_tls, meta=meta)
            elif port in IMAP_PORTS or port in IMAPS_PORTS:
                self._handle_imap_service(wrapped_sock, addr, port, use_tls=use_tls, meta=meta)
            elif port in TELNET_PORTS:
                self._handle_telnet_service(wrapped_sock, addr, port, meta=meta)
            elif port in SSH_PORTS:
                self._handle_ssh_service(wrapped_sock, addr, port, meta=meta)
            elif port in MYSQL_PORTS:
                self._handle_mysql_service(wrapped_sock, addr, port, meta=meta)
            elif port in POSTGRES_PORTS:
                self._handle_postgres_service(wrapped_sock, addr, port, meta=meta)
            elif port in REDIS_PORTS:
                self._handle_redis_service(wrapped_sock, addr, port, meta=meta)
            elif port in MEMCACHED_TCP_PORTS:
                self._handle_memcached_service(wrapped_sock, addr, port, meta=meta)
            elif port in VNC_PORTS:
                self._handle_vnc_service(wrapped_sock, addr, port, meta=meta)
            elif port in MQTT_PORTS or port in MQTTS_PORTS:
                self._handle_mqtt_service(wrapped_sock, addr, port, use_tls=use_tls, meta=meta)
            elif port in AMQP_PORTS or port in AMQPS_PORTS:
                self._handle_amqp_service(wrapped_sock, addr, port, use_tls=use_tls, meta=meta)
            elif port in LDAP_PORTS or port in LDAPS_PORTS:
                self._handle_ldap_service(wrapped_sock, addr, port, use_tls=use_tls, meta=meta)
            elif port in RTSP_PORTS:
                self._handle_rtsp_service(wrapped_sock, addr, port, meta=meta)
            elif port in DNS_TCP_PORTS:
                self._handle_dns_tcp_service(wrapped_sock, addr, port, meta=meta)
            elif port in MONGODB_PORTS:
                self._handle_mongodb_service(wrapped_sock, addr, port, meta=meta)
            else:
                self._handle_generic_tcp(wrapped_sock, addr, port, use_tls=use_tls, meta=meta)
        except ssl.SSLError as error:
            LOGGER.info("TLS error en puerto %s: %s", port, error)
            self._set_error(f"tls/{port}", str(error))
        except Exception as error:
            LOGGER.exception("TCP Error en puerto %s", port)
            self._set_error(f"tcp/{port}", str(error))
        finally:
            try:
                wrapped_sock.close()
            except Exception:
                pass

    def _handle_http_service(self, client_sock, addr, port, *, use_tls=False, meta=None):
        request_data = b""
        try:
            request_data = _read_http_request(client_sock)
        except Exception:
            request_data = b""
        scheme = "HTTPS" if use_tls else "HTTP"
        if request_data:
            request_line = request_data.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
            LOGGER.info("%s %s %s -> %s", scheme, addr[0], addr[1], request_line)
        body = (
            f"<html><head><title>{scheme} Honeypot</title>"
            '<link rel="icon" type="image/x-icon" href="/favicon.ico"></head>'
            f"<body><h1>{scheme} Honeypot</h1><p>Puerto: {port}</p>"
            "<p>Favicon de prueba activo en /favicon.ico</p></body></html>"
        ).encode("utf-8")
        response = _build_http_response(200, "OK", body, "text/html; charset=utf-8")
        if request_data:
            path = "/"
            request_line = request_data.split(b"\r\n", 1)[0].decode("utf-8", errors="replace")
            parts = request_line.split()
            if len(parts) >= 2:
                path = parts[1]
            if path == "/favicon.ico":
                response = _build_http_response(200, "OK", FAVICON_ICO, "image/x-icon")
        _safe_send(client_sock, response)
        packet = self._build_packet(
            protocol="tcp",
            port=port,
            addr=addr,
            data=request_data or b"(sin datos)",
            banner_text=f"{scheme} honeypot response",
            summary=f"{scheme} response",
            meta=meta,
        )
        self._emit_packet(packet)

    def _handle_ftp_service(self, client_sock, addr, port, *, use_tls=False, meta=None):
        banner = TCP_BANNERS.get(port, "220 FTP Honeypot Ready\r\n")
        _safe_send(client_sock, banner)
        client_sock.settimeout(READ_TIMEOUT_SECONDS)
        saw_data = b""
        for _ in range(MAX_COMMAND_ROUNDS):
            line = _recv_line(client_sock)
            if not line:
                break
            saw_data += line
            command = _decode_line(line).split(" ", 1)[0].upper()
            if command == "USER":
                _safe_send(client_sock, b"331 Password required\r\n")
            elif command == "PASS":
                _safe_send(client_sock, b"230 Login successful\r\n")
            elif command == "SYST":
                _safe_send(client_sock, b"215 UNIX Type: L8\r\n")
            elif command in {"PWD", "XPWD"}:
                _safe_send(client_sock, b'257 "/" is current directory\r\n')
            elif command == "QUIT":
                _safe_send(client_sock, b"221 Goodbye\r\n")
                break
            else:
                _safe_send(client_sock, b"502 Command not implemented\r\n")
        packet = self._build_packet(
            protocol="tcp",
            port=port,
            addr=addr,
            data=saw_data or b"(sin datos)",
            banner_text="FTP honeypot banner",
            summary="FTP session",
            meta=meta,
        )
        self._emit_packet(packet)

    def _handle_smtp_service(self, client_sock, addr, port, *, use_tls=False, meta=None):
        banner = TCP_BANNERS.get(port, "220 smtp.honeypot.local ESMTP Ready\r\n")
        _safe_send(client_sock, banner)
        client_sock.settimeout(READ_TIMEOUT_SECONDS)
        buffer = b""
        in_data_mode = False
        for _ in range(MAX_COMMAND_ROUNDS * 2):
            line_bytes = _recv_line(client_sock)
            if not line_bytes:
                break
            buffer += line_bytes
            line = _decode_line(line_bytes)
            if in_data_mode:
                if line == ".":
                    _safe_send(client_sock, b"250 2.0.0 Message queued as HP123456\r\n")
                    in_data_mode = False
                continue
            command = line.split(" ", 1)[0].upper() if line else ""
            if command in {"EHLO", "HELO"}:
                _safe_send(client_sock, b"250-honeypot.local Hello\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250-8BITMIME\r\n250 HELP\r\n")
            elif command in {"MAIL", "RCPT", "RSET", "NOOP"}:
                _safe_send(client_sock, b"250 2.1.0 Ok\r\n")
            elif command == "DATA":
                _safe_send(client_sock, b"354 End data with <CR><LF>.<CR><LF>\r\n")
                in_data_mode = True
            elif command == "STARTTLS":
                _safe_send(client_sock, b"454 4.7.0 TLS not available in this session\r\n")
            elif command == "QUIT":
                _safe_send(client_sock, b"221 2.0.0 Bye\r\n")
                break
            else:
                _safe_send(client_sock, b"500 5.5.2 Error: command not recognized\r\n")
        packet = self._build_packet(
            protocol="tcp",
            port=port,
            addr=addr,
            data=buffer or b"(sin datos)",
            banner_text="SMTP honeypot banner",
            summary="SMTP session",
            meta=meta,
        )
        self._emit_packet(packet)

    def _handle_pop3_service(self, client_sock, addr, port, *, use_tls=False, meta=None):
        _safe_send(client_sock, TCP_BANNERS.get(port, "+OK POP3 Honeypot Server Ready\r\n"))
        client_sock.settimeout(READ_TIMEOUT_SECONDS)
        buffer = b""
        for _ in range(MAX_COMMAND_ROUNDS):
            line = _recv_line(client_sock)
            if not line:
                break
            buffer += line
            command = _decode_line(line).split(" ", 1)[0].upper()
            if command == "USER":
                _safe_send(client_sock, b"+OK user accepted\r\n")
            elif command == "PASS":
                _safe_send(client_sock, b"+OK mailbox has 2 messages (320 octets)\r\n")
            elif command == "STAT":
                _safe_send(client_sock, b"+OK 2 320\r\n")
            elif command == "LIST":
                _safe_send(client_sock, b"+OK 2 messages\r\n1 120\r\n2 200\r\n.\r\n")
            elif command == "QUIT":
                _safe_send(client_sock, b"+OK Goodbye\r\n")
                break
            else:
                _safe_send(client_sock, b"-ERR Unknown command\r\n")
        packet = self._build_packet(protocol="tcp", port=port, addr=addr, data=buffer or b"(sin datos)", banner_text="POP3 honeypot banner", summary="POP3 session", meta=meta)
        self._emit_packet(packet)

    def _handle_imap_service(self, client_sock, addr, port, *, use_tls=False, meta=None):
        _safe_send(client_sock, TCP_BANNERS.get(port, "* OK IMAP4rev1 Honeypot Service Ready\r\n"))
        client_sock.settimeout(READ_TIMEOUT_SECONDS)
        buffer = b""
        for _ in range(MAX_COMMAND_ROUNDS):
            line = _recv_line(client_sock)
            if not line:
                break
            buffer += line
            text = _decode_line(line)
            parts = text.split()
            tag = parts[0] if parts else "A000"
            command = parts[1].upper() if len(parts) > 1 else ""
            if command == "CAPABILITY":
                _safe_send(client_sock, b"* CAPABILITY IMAP4rev1 AUTH=PLAIN IDLE\r\n")
                _safe_send(client_sock, f"{tag} OK CAPABILITY completed\r\n".encode())
            elif command == "LOGIN":
                _safe_send(client_sock, f"{tag} OK LOGIN completed\r\n".encode())
            elif command == "LOGOUT":
                _safe_send(client_sock, b"* BYE Logging out\r\n")
                _safe_send(client_sock, f"{tag} OK LOGOUT completed\r\n".encode())
                break
            else:
                _safe_send(client_sock, f"{tag} BAD Command not supported\r\n".encode())
        packet = self._build_packet(protocol="tcp", port=port, addr=addr, data=buffer or b"(sin datos)", banner_text="IMAP honeypot banner", summary="IMAP session", meta=meta)
        self._emit_packet(packet)

    def _handle_telnet_service(self, client_sock, addr, port, *, meta=None):
        _safe_send(client_sock, TCP_BANNERS.get(port, "Linux honeypot login: "))
        client_sock.settimeout(READ_TIMEOUT_SECONDS)
        buffer = b""
        username = _recv_line(client_sock)
        if username:
            buffer += username
            _safe_send(client_sock, b"Password: ")
            password = _recv_line(client_sock)
            if password:
                buffer += password
        _safe_send(client_sock, b"\r\nLogin incorrect\r\nConnection closed by foreign host.\r\n")
        packet = self._build_packet(protocol="tcp", port=port, addr=addr, data=buffer or b"(sin datos)", banner_text="Telnet honeypot banner", summary="Telnet login", meta=meta)
        self._emit_packet(packet)

    def _handle_ssh_service(self, client_sock, addr, port, *, meta=None):
        _safe_send(client_sock, TCP_BANNERS.get(port, "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3\r\n"))
        client_sock.settimeout(READ_TIMEOUT_SECONDS)
        data = b""
        try:
            data = client_sock.recv(MAX_PACKET_SIZE)
            if data:
                LOGGER.info("SSH packet from %s:%s", addr[0], addr[1])
        except socket.timeout:
            pass
        packet = self._build_packet(protocol="tcp", port=port, addr=addr, data=data or b"(sin datos)", banner_text="SSH honeypot banner", summary="SSH handshake", meta=meta)
        self._emit_packet(packet)

    def _handle_mysql_service(self, client_sock, addr, port, *, meta=None):
        protocol_payload = (
            b"\x0a"
            b"8.0.30-honeypot\x00"
            b"\x01\x00\x00\x00"
            b"abcdefgh\x00"
            b"\xff\xf7"
            b"\x21"
            b"\x02\x00"
            b"\xff\xdf"
            b"\x15"
            + (b"\x00" * 10)
            + b"ijklmnopqrstuvwx\x00"
            + b"mysql_native_password\x00"
        )
        _safe_send(client_sock, len(protocol_payload).to_bytes(3, "little") + b"\x00" + protocol_payload)
        client_sock.settimeout(READ_TIMEOUT_SECONDS)
        data = b""
        try:
            data = client_sock.recv(MAX_PACKET_SIZE)
            if data:
                payload = b"\xff\x15\x04#28000Access denied"
                _safe_send(client_sock, len(payload).to_bytes(3, "little") + b"\x02" + payload)
        except socket.timeout:
            pass
        packet = self._build_packet(protocol="tcp", port=port, addr=addr, data=data or b"(sin datos)", banner_text="MySQL honeypot banner", summary="MySQL handshake", meta=meta)
        self._emit_packet(packet)

    def _handle_postgres_service(self, client_sock, addr, port, *, meta=None):
        _safe_send(client_sock, TCP_BANNERS.get(port, "POSTGRES 13.0 Honeypot\r\n"))
        client_sock.settimeout(READ_TIMEOUT_SECONDS)
        data = b""
        try:
            data = client_sock.recv(MAX_PACKET_SIZE)
            if data:
                if len(data) >= 8 and data[:4] == b"\x00\x00\x00\x08" and data[4:8] == b"\x04\xd2\x16/":
                    _safe_send(client_sock, b"N")
                    data += client_sock.recv(MAX_PACKET_SIZE)
                _safe_send(client_sock, _build_postgres_error_packet())
        except socket.timeout:
            pass
        packet = self._build_packet(protocol="tcp", port=port, addr=addr, data=data or b"(sin datos)", banner_text="PostgreSQL honeypot banner", summary="Postgres handshake", meta=meta)
        self._emit_packet(packet)

    def _handle_redis_service(self, client_sock, addr, port, *, meta=None):
        _safe_send(client_sock, TCP_BANNERS.get(port, b"-NOAUTH Authentication required.\r\n"))
        client_sock.settimeout(READ_TIMEOUT_SECONDS)
        data = b""
        for _ in range(MAX_COMMAND_ROUNDS):
            try:
                chunk = client_sock.recv(MAX_PACKET_SIZE)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
            upper_data = chunk.upper()
            if b"PING" in upper_data:
                _safe_send(client_sock, b"+PONG\r\n")
            elif b"INFO" in upper_data:
                body = b"# Server\r\nredis_version:7.0.11\r\nrole:master"
                _safe_send(client_sock, b"$" + str(len(body)).encode() + b"\r\n" + body + b"\r\n")
            elif b"SET" in upper_data:
                _safe_send(client_sock, b"+OK\r\n")
            elif b"GET" in upper_data:
                _safe_send(client_sock, b"$-1\r\n")
            elif b"QUIT" in upper_data:
                _safe_send(client_sock, b"+OK\r\n")
                break
            else:
                _safe_send(client_sock, b"-ERR unknown command\r\n")
        packet = self._build_packet(protocol="tcp", port=port, addr=addr, data=data or b"(sin datos)", banner_text="Redis honeypot banner", summary="Redis session", meta=meta)
        self._emit_packet(packet)

    def _handle_memcached_service(self, client_sock, addr, port, *, meta=None):
        _safe_send(client_sock, b"STAT pid 2134\r\nEND\r\n")
        client_sock.settimeout(READ_TIMEOUT_SECONDS)
        data = b""
        for _ in range(MAX_COMMAND_ROUNDS):
            line = _recv_line(client_sock)
            if not line:
                break
            data += line
            parts = _decode_line(line).split()
            command = parts[0].lower() if parts else ""
            if command == "version":
                _safe_send(client_sock, b"VERSION 1.6.9\r\n")
            elif command == "stats":
                _safe_send(client_sock, b"STAT version 1.6.9\r\nSTAT uptime 86400\r\nEND\r\n")
            elif command == "get":
                _safe_send(client_sock, b"END\r\n")
            elif command in {"set", "add", "replace"}:
                _safe_send(client_sock, b"STORED\r\n")
            elif command == "quit":
                break
            else:
                _safe_send(client_sock, b"ERROR\r\n")
        packet = self._build_packet(protocol="tcp", port=port, addr=addr, data=data or b"(sin datos)", banner_text="Memcached honeypot banner", summary="Memcached session", meta=meta)
        self._emit_packet(packet)

    def _handle_vnc_service(self, client_sock, addr, port, *, meta=None):
        _safe_send(client_sock, TCP_BANNERS.get(port, b"RFB 003.008\n"))
        client_sock.settimeout(READ_TIMEOUT_SECONDS)
        data = b""
        try:
            data = client_sock.recv(MAX_PACKET_SIZE)
            if data:
                _safe_send(client_sock, b"\x01\x01")
        except socket.timeout:
            pass
        packet = self._build_packet(protocol="tcp", port=port, addr=addr, data=data or b"(sin datos)", banner_text="VNC honeypot banner", summary="VNC handshake", meta=meta)
        self._emit_packet(packet)

    def _handle_mqtt_service(self, client_sock, addr, port, *, use_tls=False, meta=None):
        client_sock.settimeout(READ_TIMEOUT_SECONDS)
        data = b""
        for _ in range(MAX_COMMAND_ROUNDS):
            try:
                packet = client_sock.recv(MAX_PACKET_SIZE)
            except socket.timeout:
                break
            if not packet:
                break
            data += packet
            packet_type = packet[0] >> 4
            if packet_type == 1:
                _safe_send(client_sock, b"\x20\x02\x00\x00")
            elif packet_type == 8:
                _safe_send(client_sock, b"\x90\x03\x00\x01\x00")
            elif packet_type == 12:
                _safe_send(client_sock, b"\xd0\x00")
            elif packet_type == 14:
                break
            else:
                _safe_send(client_sock, b"\xd0\x00")
        packet = self._build_packet(protocol="tcp", port=port, addr=addr, data=data or b"(sin datos)", banner_text="MQTT honeypot banner", summary="MQTT session", meta=meta)
        self._emit_packet(packet)

    def _handle_amqp_service(self, client_sock, addr, port, *, use_tls=False, meta=None):
        _safe_send(client_sock, TCP_BANNERS.get(port, b"AMQP\x00\x00\x09\x01"))
        client_sock.settimeout(READ_TIMEOUT_SECONDS)
        data = b""
        try:
            data = client_sock.recv(MAX_PACKET_SIZE)
            if data:
                _safe_send(client_sock, b"AMQP\x00\x00\x09\x01")
        except socket.timeout:
            pass
        packet = self._build_packet(protocol="tcp", port=port, addr=addr, data=data or b"(sin datos)", banner_text="AMQP honeypot banner", summary="AMQP session", meta=meta)
        self._emit_packet(packet)

    def _handle_ldap_service(self, client_sock, addr, port, *, use_tls=False, meta=None):
        _safe_send(client_sock, TCP_BANNERS.get(port, "LDAP Honeypot Service Ready\r\n"))
        client_sock.settimeout(READ_TIMEOUT_SECONDS)
        data = b""
        try:
            data = client_sock.recv(MAX_PACKET_SIZE)
            if data:
                _safe_send(client_sock, _build_ldap_bind_response(data))
        except socket.timeout:
            pass
        packet = self._build_packet(protocol="tcp", port=port, addr=addr, data=data or b"(sin datos)", banner_text="LDAP honeypot banner", summary="LDAP session", meta=meta)
        self._emit_packet(packet)

    def _handle_rtsp_service(self, client_sock, addr, port, *, meta=None):
        _safe_send(client_sock, TCP_BANNERS.get(port, "RTSP/1.0 200 OK\r\nServer: Live555-Honeypot\r\n\r\n"))
        request = _read_http_request(client_sock)
        if request:
            _safe_send(client_sock, _build_rtsp_response(request.decode("utf-8", errors="replace")))
        packet = self._build_packet(protocol="tcp", port=port, addr=addr, data=request or b"(sin datos)", banner_text="RTSP honeypot banner", summary="RTSP session", meta=meta)
        self._emit_packet(packet)

    def _handle_dns_tcp_service(self, client_sock, addr, port, *, meta=None):
        client_sock.settimeout(READ_TIMEOUT_SECONDS)
        packet_data = b""
        try:
            packet = client_sock.recv(MAX_PACKET_SIZE)
            if not packet:
                return
            packet_data = packet
            if len(packet) < 2:
                return
            query_length = int.from_bytes(packet[:2], "big")
            query = packet[2:]
            while len(query) < query_length:
                chunk = client_sock.recv(MAX_PACKET_SIZE)
                if not chunk:
                    break
                query += chunk
            query = query[:query_length]
            response_ip = self._socket_listener_ip(client_sock, addr[0])
            response_body, questions = _build_dns_response(query, response_ip)
            if questions:
                domains = ", ".join(question["domain"] for question in questions)
                LOGGER.info("DNS query %s -> %s", addr[0], domains)
                if meta is None:
                    meta = {}
                meta["dns"] = {"questions": questions, "response_ip": response_ip}
            _safe_send(client_sock, len(response_body).to_bytes(2, "big") + response_body)
        except socket.timeout:
            pass
        packet = self._build_packet(protocol="tcp", port=port, addr=addr, data=packet_data or b"(sin datos)", banner_text="DNS honeypot banner", summary="DNS query", meta=meta)
        self._emit_packet(packet)

    def _handle_mongodb_service(self, client_sock, addr, port, *, meta=None):
        _safe_send(
            client_sock,
            TCP_BANNERS.get(
                port,
                "It looks like you are trying to access MongoDB over HTTP on the native driver port.\n",
            ),
        )
        client_sock.settimeout(READ_TIMEOUT_SECONDS)
        data = b""
        try:
            data = client_sock.recv(MAX_PACKET_SIZE)
        except socket.timeout:
            pass
        packet = self._build_packet(protocol="tcp", port=port, addr=addr, data=data or b"(sin datos)", banner_text="MongoDB honeypot banner", summary="MongoDB session", meta=meta)
        self._emit_packet(packet)

    def _handle_generic_tcp(self, client_sock, addr, port, *, use_tls=False, meta=None):
        banner = TCP_BANNERS.get(port, "220 Honeypot Service Ready\r\n")
        _safe_send(client_sock, banner)
        client_sock.settimeout(READ_TIMEOUT_SECONDS)
        data = b""
        for _ in range(MAX_COMMAND_ROUNDS):
            try:
                chunk = client_sock.recv(MAX_PACKET_SIZE)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
            if port in SMB_PORTS or port in RDP_PORTS:
                _safe_send(client_sock, banner)
        packet = self._build_packet(protocol="tcp", port=port, addr=addr, data=data or b"(sin datos)", banner_text=str(banner), summary="Generic TCP session", meta=meta)
        self._emit_packet(packet)

    def _handle_udp(self, sock, addr, port, data: bytes):
        LOGGER.info("UDP %s:%s -> %s", addr[0], addr[1], port)
        response = self._udp_response_for(port, data, addr)
        if response:
            try:
                sock.sendto(response, addr)
            except Exception:
                pass
        meta: dict[str, Any] = {}
        if port in DNS_UDP_PORTS:
            response_ip = self._socket_listener_ip(sock, addr[0])
            _, questions = _build_dns_response(data, response_ip)
            if questions:
                meta["dns"] = {"questions": questions, "response_ip": response_ip}
        packet = self._build_packet(protocol="udp", port=port, addr=addr, data=data, banner_text="UDP honeypot banner", summary="UDP datagram", meta=meta)
        self._emit_packet(packet)

    def _udp_response_for(self, port: int, data: bytes, addr):
        if port == 68:
            return None
        if port in DNS_UDP_PORTS:
            response_ip = self._socket_listener_ip(None, addr[0])
            response, _questions = _build_dns_response(data, response_ip)
            return response
        if port in NTP_UDP_PORTS:
            return _build_ntp_response(data)
        if port in SIP_UDP_PORTS:
            return _build_sip_response(data, addr)
        if port in SNMP_UDP_PORTS:
            return b"\x30\x29\x02\x01\x01\x04\x06public\xa2\x1c\x02\x04\x00\x00\x00\x01\x02\x01\x00\x02\x01\x00\x30\x0e\x30\x0c\x06\x08+\x06\x01\x02\x01\x01\x01\x00\x05\x00"
        if port in SYSLOG_UDP_PORTS:
            return UDP_BANNERS[514].encode("utf-8")
        if port in RADIUS_UDP_PORTS:
            return str(UDP_BANNERS[port]).encode("utf-8")
        if port in MDNS_UDP_PORTS:
            return UDP_BANNERS[5353]
        banner = UDP_BANNERS.get(port, "Honeypot UDP Service\n")
        return banner.encode("utf-8") if isinstance(banner, str) else banner
