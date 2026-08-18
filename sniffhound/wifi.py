"""802.11 monitor-mode frame parsing: Radiotap header + 802.11 MAC header +
management-frame information elements.

Deliberately narrow in scope, matching the manual WiFi monitor-mode toggle
this backs: only beacon/probe/deauth/disassoc/auth management frames are
decoded in any detail (everything a SOC operator needs for rogue-AP and
deauth-flood detection). Data/control frames get a one-line generic summary
only — they're almost always encrypted and there's nothing useful to extract
without keys. No channel hopping/selection here either (see netlink.py).
"""

from __future__ import annotations

from .utils import format_mac, utc_now

RADIOTAP_FIELD_TABLE = [
    # (present-bit, field size in bytes, alignment)
    (0, 8, 8),  # TSFT
    (1, 1, 1),  # Flags
    (2, 1, 1),  # Rate
    (3, 4, 2),  # Channel (frequency u16 + flags u16)
    (4, 2, 2),  # FHSS
    (5, 1, 1),  # Antenna signal (dBm, signed)
    (6, 1, 1),  # Antenna noise (dBm, signed)
    (7, 2, 2),  # Lock quality
    (8, 2, 2),  # TX attenuation
    (9, 2, 2),  # dB TX attenuation
    (10, 1, 1),  # dBm TX power
    (11, 1, 1),  # Antenna
    (12, 1, 1),  # dB antenna signal
    (13, 1, 1),  # dB antenna noise
]

DOT11_TYPE_MGMT = 0
DOT11_TYPE_CTRL = 1
DOT11_TYPE_DATA = 2

DOT11_MGMT_SUBTYPES = {
    0: "assoc-req", 1: "assoc-resp", 2: "reassoc-req", 3: "reassoc-resp",
    4: "probe-req", 5: "probe-resp", 8: "beacon", 9: "atim",
    10: "disassoc", 11: "auth", 12: "deauth", 13: "action",
}


def parse_radiotap(data: bytes) -> tuple[dict, int]:
    """Best-effort Radiotap header parse. `it_len` (the only field this
    format guarantees is always reliable) is used to locate the 802.11
    header; optional fields (signal/channel) degrade to None on any surprise
    rather than raising."""
    fields = {"signal_dbm": None, "channel_freq": None}
    if len(data) < 8:
        return fields, 0
    it_len = int.from_bytes(data[2:4], "little")
    if it_len < 8:
        return fields, it_len
    try:
        present_words = []
        pos = 4
        while pos + 4 <= it_len and pos + 4 <= len(data):
            word = int.from_bytes(data[pos : pos + 4], "little")
            present_words.append(word)
            pos += 4
            if not (word & 0x80000000):
                break
        first_present = present_words[0] if present_words else 0
        field_pos = pos
        for bit, size, align in RADIOTAP_FIELD_TABLE:
            if not (first_present & (1 << bit)):
                continue
            if align > 1:
                remainder = field_pos % align
                if remainder:
                    field_pos += align - remainder
            if field_pos + size > it_len or field_pos + size > len(data):
                break
            if bit == 3:
                fields["channel_freq"] = int.from_bytes(data[field_pos : field_pos + 2], "little")
            elif bit == 5:
                signal = data[field_pos]
                fields["signal_dbm"] = signal - 256 if signal >= 128 else signal
            field_pos += size
    except Exception:
        pass
    return fields, it_len


def parse_information_elements(body: bytes) -> dict:
    result: dict = {}
    pos = 0
    while pos + 2 <= len(body):
        tag = body[pos]
        length = body[pos + 1]
        pos += 2
        if pos + length > len(body):
            break
        value = body[pos : pos + length]
        pos += length
        if tag == 0:  # SSID
            try:
                result["ssid"] = value.decode("utf-8", errors="replace") if length else ""
            except Exception:
                result["ssid"] = ""
        elif tag == 3 and length >= 1:  # DS Parameter Set (channel)
            result["channel"] = value[0]
    return result


def _decode_management_body(packet: dict, subtype_name: str, body: bytes) -> None:
    bssid = packet.get("wifi_bssid") or ""
    if subtype_name in ("beacon", "probe-resp"):
        ies = parse_information_elements(body[12:] if len(body) >= 12 else b"")
        ssid = ies.get("ssid", "")
        packet["wifi_ssid"] = ssid
        channel = ies.get("channel")
        if channel:
            packet["wifi_channel"] = channel
        label = ssid if ssid else "<hidden>"
        summary = f"802.11 {subtype_name} SSID='{label}' BSSID={bssid or '?'}"
        if channel:
            summary += f" channel={channel}"
        packet["summary"] = summary
        packet["banner_text"] = summary
    elif subtype_name == "probe-req":
        ies = parse_information_elements(body)
        ssid = ies.get("ssid", "")
        packet["wifi_ssid"] = ssid
        label = ssid if ssid else "<wildcard>"
        summary = f"802.11 probe-req SSID='{label}' from {packet.get('eth_src') or '?'}"
        packet["summary"] = summary
        packet["banner_text"] = summary
    elif subtype_name in ("deauth", "disassoc"):
        reason_code = int.from_bytes(body[0:2], "little") if len(body) >= 2 else 0
        packet["wifi_reason_code"] = reason_code
        summary = f"802.11 {subtype_name} BSSID={bssid or '?'} reason={reason_code}"
        packet["summary"] = summary
        packet["banner_text"] = summary
    elif subtype_name == "auth":
        algo = int.from_bytes(body[0:2], "little") if len(body) >= 2 else 0
        seq = int.from_bytes(body[2:4], "little") if len(body) >= 4 else 0
        summary = f"802.11 auth algo={algo} seq={seq} BSSID={bssid or '?'}"
        packet["summary"] = summary
        packet["banner_text"] = summary
    else:
        summary = f"802.11 {subtype_name} BSSID={bssid or '?'}"
        packet["summary"] = summary
        packet["banner_text"] = summary


def parse_80211_frame(data: bytes, *, interface: str) -> dict | None:
    from .sniffer import build_base_packet

    if len(data) < 10:
        return None
    radiotap_fields, it_len = parse_radiotap(data)
    if it_len <= 0 or it_len > len(data):
        return None
    frame = data[it_len:]
    if len(frame) < 10:
        return None

    fc = int.from_bytes(frame[0:2], "little")
    ftype = (fc >> 2) & 0x3
    subtype = (fc >> 4) & 0xF
    to_ds = bool(fc & 0x0100)
    from_ds = bool(fc & 0x0200)

    addr1 = format_mac(frame[4:10]) if len(frame) >= 10 else ""
    addr2 = ""
    addr3 = ""
    body_offset = 10
    has_addr23 = ftype in (DOT11_TYPE_MGMT, DOT11_TYPE_DATA) or (
        ftype == DOT11_TYPE_CTRL and subtype in (0x8, 0x9, 0xB)
    )
    if has_addr23:
        if len(frame) >= 16:
            addr2 = format_mac(frame[10:16])
        if len(frame) >= 22:
            addr3 = format_mac(frame[16:22])
        body_offset = 24
        if to_ds and from_ds and len(frame) >= 30:
            body_offset = 30
        if ftype == DOT11_TYPE_DATA and (subtype & 0x08) and len(frame) >= body_offset + 2:
            body_offset += 2  # QoS control field

    now = utc_now()
    packet = build_base_packet(now, interface, data, frame, eth_src=addr2 or addr1, eth_dst=addr1, eth_type=0)
    packet["wifi_channel"] = radiotap_fields.get("channel_freq")
    packet["wifi_signal_dbm"] = radiotap_fields.get("signal_dbm")
    packet["wifi_bssid"] = addr3 or addr2 or ""

    if ftype == DOT11_TYPE_MGMT:
        packet["proto"] = "wifi-mgmt"
        subtype_name = DOT11_MGMT_SUBTYPES.get(subtype, f"subtype-{subtype}")
        packet["wifi_subtype"] = subtype_name
        _decode_management_body(packet, subtype_name, frame[body_offset:])
    elif ftype == DOT11_TYPE_DATA:
        packet["proto"] = "wifi-data"
        packet["wifi_subtype"] = f"data-{subtype}"
        summary = f"802.11 data frame {addr2 or '?'} -> {addr1 or '?'} (encrypted)"
        packet["summary"] = summary
        packet["banner_text"] = summary
    else:
        packet["proto"] = "wifi-ctrl"
        packet["wifi_subtype"] = f"ctrl-{subtype}"
        summary = f"802.11 control frame subtype {subtype} -> {addr1 or '?'}"
        packet["summary"] = summary
        packet["banner_text"] = summary

    return packet
