"""802.11 monitor-mode frame parsing: Radiotap header + 802.11 MAC header +
information elements for management frames, plus best-effort decoding of
control and data frame headers.

Management frames get the deepest decode (SSID/BSSID/channel/capability/
status for everything a SOC operator needs for rogue-AP and deauth-flood
detection). Data frame *payloads* are almost always encrypted and there is
nothing useful to extract without keys, but the MAC header itself - DS
status (STA->AP/AP->STA/WDS), QoS/protected flags, retry - is cleartext and
decoded here. Control frames (RTS/CTS/ACK/Block Ack/PS-Poll/CF-End) are named
and their addresses resolved rather than left as a bare subtype number. No
channel hopping/selection here either (see netlink.py).
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
    14: "action-no-ack",
}

# Subtypes that carry an Address 2 (transmitter address) field in addition
# to Address 1 (receiver) - the rest (CTS, ACK) are the bare 10-byte minimal
# control frame with only a receiver address.
DOT11_CTRL_SUBTYPES = {
    2: "trigger", 4: "beamforming-report-poll", 5: "vht-ndp-announcement",
    6: "control-frame-extension", 7: "control-wrapper",
    8: "block-ack-req", 9: "block-ack", 10: "ps-poll", 11: "rts",
    12: "cts", 13: "ack", 14: "cf-end", 15: "cf-end-ack",
}
DOT11_CTRL_HAS_ADDR2 = {7, 8, 9, 10, 11, 14, 15}

DOT11_ACTION_CATEGORIES = {
    0: "spectrum-mgmt", 1: "qos", 2: "dls", 3: "block-ack", 4: "public",
    5: "radio-measurement", 6: "fast-bss-transition", 7: "ht",
    8: "sa-query", 9: "protected-dual", 10: "wnm", 11: "unprotected-wnm",
    12: "tdls", 13: "mesh", 14: "multihop", 15: "self-protected",
    17: "wnm-notification", 126: "vendor-protected", 127: "vendor",
}


def parse_radiotap(data: bytes) -> tuple[dict, int]:
    """Best-effort Radiotap header parse. `it_len` (the only field this
    format guarantees is always reliable) is used to locate the 802.11
    header; optional fields (signal/channel/rate) degrade to None on any
    surprise rather than raising."""
    fields = {"signal_dbm": None, "channel_freq": None, "rate_mbps": None}
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
            if bit == 2:
                fields["rate_mbps"] = data[field_pos] * 0.5
            elif bit == 3:
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
        elif tag == 1 and length >= 1:  # Supported Rates (Mbps, MSB = basic-rate flag)
            result["rates_mbps"] = [round((byte & 0x7F) * 0.5, 1) for byte in value]
        elif tag == 48 and length >= 2:  # RSN (WPA2/WPA3)
            result["rsn"] = True
        elif tag == 221 and length >= 4 and value[0:3] == b"\x00\x50\xf2" and value[3] == 1:
            result["wpa"] = True  # Microsoft OUI, WPA vendor element
    return result


def _capability_flags(capability: int) -> list[str]:
    flags = []
    if capability & 0x0001:
        flags.append("ess")
    if capability & 0x0002:
        flags.append("ibss")
    if capability & 0x0010:
        flags.append("privacy")
    if capability & 0x0400:
        flags.append("short-preamble")
    if capability & 0x1000:
        flags.append("short-slot")
    return flags


def _security_label(ies: dict) -> str:
    if ies.get("rsn"):
        return "WPA2/WPA3"
    if ies.get("wpa"):
        return "WPA"
    return ""


def _decode_management_body(packet: dict, subtype_name: str, body: bytes) -> None:
    bssid = packet.get("wifi_bssid") or ""
    if subtype_name in ("beacon", "probe-resp"):
        # Fixed fields: timestamp(8) + beacon interval(2) + capability(2) = 12B, then IEs.
        capability = int.from_bytes(body[10:12], "little") if len(body) >= 12 else 0
        ies = parse_information_elements(body[12:] if len(body) >= 12 else b"")
        ssid = ies.get("ssid", "")
        packet["wifi_ssid"] = ssid
        channel = ies.get("channel")
        if channel:
            packet["wifi_channel"] = channel
        security = _security_label(ies)
        if security:
            packet["wifi_security"] = security
        cap_flags = _capability_flags(capability)
        label = ssid if ssid else "<hidden>"
        summary = f"802.11 {subtype_name} SSID='{label}' BSSID={bssid or '?'}"
        if channel:
            summary += f" channel={channel}"
        summary += f" security={security or 'open'}"
        if "short-preamble" in cap_flags:
            summary += " short-preamble"
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
    elif subtype_name in ("assoc-req", "reassoc-req"):
        # assoc-req: capability(2) + listen interval(2), then IEs (offset 4).
        # reassoc-req: capability(2) + listen interval(2) + current AP addr(6), then IEs (offset 10).
        ie_offset = 10 if subtype_name == "reassoc-req" else 4
        capability = int.from_bytes(body[0:2], "little") if len(body) >= 2 else 0
        ies = parse_information_elements(body[ie_offset:] if len(body) >= ie_offset else b"")
        ssid = ies.get("ssid", "")
        packet["wifi_ssid"] = ssid
        security = _security_label(ies)
        if security:
            packet["wifi_security"] = security
        cap_flags = _capability_flags(capability)
        summary = f"802.11 {subtype_name} SSID='{ssid or '?'}' BSSID={bssid or '?'} security={security or 'open'}"
        if cap_flags:
            summary += f" caps={','.join(cap_flags)}"
        packet["summary"] = summary
        packet["banner_text"] = summary
    elif subtype_name in ("assoc-resp", "reassoc-resp"):
        # capability(2) + status code(2) + association ID(2), then IEs.
        status = int.from_bytes(body[2:4], "little") if len(body) >= 4 else None
        aid = int.from_bytes(body[4:6], "little") & 0x3FFF if len(body) >= 6 else None
        packet["wifi_status_code"] = status
        outcome = "success" if status == 0 else f"failed(status={status})"
        summary = f"802.11 {subtype_name} {outcome} BSSID={bssid or '?'}"
        if aid:
            summary += f" AID={aid}"
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
        status = int.from_bytes(body[4:6], "little") if len(body) >= 6 else None
        algo_name = {0: "open", 1: "shared-key", 2: "fast-bss-transition", 3: "sae"}.get(algo, str(algo))
        summary = f"802.11 auth algo={algo_name} seq={seq} BSSID={bssid or '?'}"
        if status is not None:
            summary += " success" if status == 0 else f" failed(status={status})"
        packet["summary"] = summary
        packet["banner_text"] = summary
    elif subtype_name in ("action", "action-no-ack"):
        category = body[0] if body else None
        action_code = body[1] if len(body) >= 2 else None
        category_name = DOT11_ACTION_CATEGORIES.get(category, str(category) if category is not None else "?")
        packet["wifi_action_category"] = category_name
        summary = f"802.11 {subtype_name} category={category_name}"
        if action_code is not None:
            summary += f" action={action_code}"
        summary += f" BSSID={bssid or '?'}"
        packet["summary"] = summary
        packet["banner_text"] = summary
    else:
        summary = f"802.11 {subtype_name} BSSID={bssid or '?'}"
        packet["summary"] = summary
        packet["banner_text"] = summary


def _decode_control_frame(packet: dict, subtype: int, addr1: str, addr2: str) -> None:
    name = DOT11_CTRL_SUBTYPES.get(subtype, f"subtype-{subtype}")
    packet["wifi_subtype"] = f"ctrl-{name}"
    if name in ("rts", "block-ack-req", "block-ack", "ps-poll"):
        summary = f"802.11 {name.upper() if name == 'rts' else name} {addr2 or '?'} -> {addr1 or '?'}"
    elif name in ("cts", "ack"):
        summary = f"802.11 {name.upper()} -> {addr1 or '?'}"
    elif name in ("cf-end", "cf-end-ack"):
        summary = f"802.11 {name} {addr2 or '?'} -> {addr1 or '?'}"
    else:
        summary = f"802.11 control ({name}) -> {addr1 or '?'}"
    packet["summary"] = summary
    packet["banner_text"] = summary


def _decode_data_frame(packet: dict, subtype: int, addr1: str, addr2: str, to_ds: bool, from_ds: bool, protected: bool) -> None:
    if to_ds and from_ds:
        ds_status = "WDS"
    elif to_ds:
        ds_status = "STA->AP"
    elif from_ds:
        ds_status = "AP->STA"
    else:
        ds_status = "IBSS/direct"
    is_qos = bool(subtype & 0x08)
    is_null = subtype in (4, 6, 12, 14)  # null / cf-poll-null / qos-null / qos-cf-poll-null
    packet["wifi_ds_status"] = ds_status
    packet["wifi_qos"] = is_qos
    packet["wifi_protected"] = protected
    kind = "QoS data" if is_qos and not is_null else "QoS null" if is_qos and is_null else "null" if is_null else "data"
    summary = f"802.11 {kind} {addr2 or '?'} -> {addr1 or '?'} [{ds_status}]"
    if protected:
        summary += " (encrypted)"
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
    retry = bool(fc & 0x0800)
    protected = bool(fc & 0x4000)

    addr1 = format_mac(frame[4:10]) if len(frame) >= 10 else ""
    addr2 = ""
    addr3 = ""
    addr4 = ""
    body_offset = 10
    has_addr23 = ftype in (DOT11_TYPE_MGMT, DOT11_TYPE_DATA) or (
        ftype == DOT11_TYPE_CTRL and subtype in DOT11_CTRL_HAS_ADDR2
    )
    if has_addr23:
        if len(frame) >= 16:
            addr2 = format_mac(frame[10:16])
        if ftype == DOT11_TYPE_CTRL:
            # Control frames with an Address 2 stop there - no Address 3/4,
            # no QoS/data body to walk past.
            body_offset = 16
        else:
            if len(frame) >= 22:
                addr3 = format_mac(frame[16:22])
            body_offset = 24
            if to_ds and from_ds and len(frame) >= 30:
                addr4 = format_mac(frame[24:30])
                body_offset = 30
            if ftype == DOT11_TYPE_DATA and (subtype & 0x08) and len(frame) >= body_offset + 2:
                body_offset += 2  # QoS control field

    now = utc_now()
    packet = build_base_packet(now, interface, data, frame, eth_src=addr2 or addr1, eth_dst=addr1, eth_type=0)
    packet["wifi_channel"] = radiotap_fields.get("channel_freq")
    packet["wifi_signal_dbm"] = radiotap_fields.get("signal_dbm")
    packet["wifi_rate_mbps"] = radiotap_fields.get("rate_mbps")
    packet["wifi_bssid"] = addr3 or addr2 or ""
    packet["wifi_addr4"] = addr4
    packet["wifi_retry"] = retry

    if ftype == DOT11_TYPE_MGMT:
        packet["proto"] = "wifi-mgmt"
        subtype_name = DOT11_MGMT_SUBTYPES.get(subtype, f"subtype-{subtype}")
        packet["wifi_subtype"] = subtype_name
        _decode_management_body(packet, subtype_name, frame[body_offset:])
    elif ftype == DOT11_TYPE_DATA:
        packet["proto"] = "wifi-data"
        _decode_data_frame(packet, subtype, addr1, addr2, to_ds, from_ds, protected)
    else:
        packet["proto"] = "wifi-ctrl"
        _decode_control_frame(packet, subtype, addr1, addr2)

    return packet
