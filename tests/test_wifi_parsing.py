from __future__ import annotations

import struct
import unittest

from sniffhound.wifi import parse_80211_frame, parse_radiotap


def _mac(text: str) -> bytes:
    return bytes(int(part, 16) for part in text.split(":"))


def _build_radiotap(signal_dbm: int | None = None) -> bytes:
    if signal_dbm is None:
        it_len = 8
        return struct.pack("<BBHI", 0, 0, it_len, 0)
    present = 1 << 5  # antenna signal
    it_len = 8 + 1
    header = struct.pack("<BBHI", 0, 0, it_len, present)
    return header + bytes([signal_dbm & 0xFF])


def _build_mgmt_header(subtype: int, addr1: str, addr2: str, addr3: str) -> bytes:
    fc_val = (subtype << 4) | (0 << 2) | 0  # type=management
    frame = struct.pack("<H", fc_val)
    frame += struct.pack("<H", 0)  # duration
    frame += _mac(addr1) + _mac(addr2) + _mac(addr3)
    frame += struct.pack("<H", 0)  # seq ctrl
    return frame


def _ie(tag: int, value: bytes) -> bytes:
    return bytes([tag, len(value)]) + value


class TestParseRadiotap(unittest.TestCase):
    def test_minimal_header_no_optional_fields(self):
        fields, it_len = parse_radiotap(_build_radiotap())
        self.assertEqual(it_len, 8)
        self.assertIsNone(fields["signal_dbm"])

    def test_signal_field_signed_negative(self):
        fields, it_len = parse_radiotap(_build_radiotap(signal_dbm=-42))
        self.assertEqual(it_len, 9)
        self.assertEqual(fields["signal_dbm"], -42)

    def test_truncated_header_degrades_gracefully(self):
        fields, it_len = parse_radiotap(b"\x00\x00")
        self.assertEqual(it_len, 0)
        self.assertIsNone(fields["signal_dbm"])


class TestParse80211Frame(unittest.TestCase):
    def test_beacon_extracts_ssid_bssid_channel(self):
        mgmt = _build_mgmt_header(8, "ff:ff:ff:ff:ff:ff", "aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff")
        fixed = b"\x00" * 8 + struct.pack("<H", 100) + struct.pack("<H", 0x0011)
        body = fixed + _ie(0, b"TestNet") + _ie(3, bytes([6]))
        data = _build_radiotap(signal_dbm=-40) + mgmt + body
        packet = parse_80211_frame(data, interface="wlan0mon")
        self.assertIsNotNone(packet)
        self.assertEqual(packet["proto"], "wifi-mgmt")
        self.assertEqual(packet["wifi_subtype"], "beacon")
        self.assertEqual(packet["wifi_ssid"], "TestNet")
        self.assertEqual(packet["wifi_bssid"], "aa:bb:cc:dd:ee:ff")
        self.assertEqual(packet["wifi_channel"], 6)
        self.assertEqual(packet["wifi_signal_dbm"], -40)
        self.assertIn("TestNet", packet["summary"])

    def test_hidden_ssid_beacon(self):
        mgmt = _build_mgmt_header(8, "ff:ff:ff:ff:ff:ff", "11:22:33:44:55:66", "11:22:33:44:55:66")
        fixed = b"\x00" * 12
        body = fixed + _ie(0, b"")
        data = _build_radiotap() + mgmt + body
        packet = parse_80211_frame(data, interface="wlan0mon")
        self.assertEqual(packet["wifi_ssid"], "")
        self.assertIn("<hidden>", packet["summary"])

    def test_probe_request(self):
        mgmt = _build_mgmt_header(4, "ff:ff:ff:ff:ff:ff", "aa:aa:aa:aa:aa:aa", "ff:ff:ff:ff:ff:ff")
        body = _ie(0, b"MyNetwork")
        data = _build_radiotap() + mgmt + body
        packet = parse_80211_frame(data, interface="wlan0mon")
        self.assertEqual(packet["wifi_subtype"], "probe-req")
        self.assertEqual(packet["wifi_ssid"], "MyNetwork")

    def test_deauth_reason_code(self):
        mgmt = _build_mgmt_header(12, "11:22:33:44:55:66", "aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff")
        body = struct.pack("<H", 7)
        data = _build_radiotap() + mgmt + body
        packet = parse_80211_frame(data, interface="wlan0mon")
        self.assertEqual(packet["wifi_subtype"], "deauth")
        self.assertEqual(packet["wifi_reason_code"], 7)
        self.assertIn("reason=7", packet["summary"])

    def test_disassoc_reason_code(self):
        mgmt = _build_mgmt_header(10, "11:22:33:44:55:66", "aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff")
        body = struct.pack("<H", 3)
        data = _build_radiotap() + mgmt + body
        packet = parse_80211_frame(data, interface="wlan0mon")
        self.assertEqual(packet["wifi_subtype"], "disassoc")
        self.assertEqual(packet["wifi_reason_code"], 3)

    def test_data_frame_gets_generic_summary_without_decoding(self):
        fc_val = (0 << 4) | (2 << 2) | 0  # type=data, subtype=0
        frame = struct.pack("<H", fc_val) + struct.pack("<H", 0)
        frame += _mac("aa:aa:aa:aa:aa:aa") + _mac("bb:bb:bb:bb:bb:bb") + _mac("cc:cc:cc:cc:cc:cc")
        frame += struct.pack("<H", 0)
        data = _build_radiotap() + frame + b"\xde\xad\xbe\xef"
        packet = parse_80211_frame(data, interface="wlan0mon")
        self.assertEqual(packet["proto"], "wifi-data")
        self.assertIn("encrypted", packet["summary"])

    def test_control_frame_minimal(self):
        fc_val = (0xD << 4) | (1 << 2) | 0  # type=control, subtype=ACK(0xD)
        frame = struct.pack("<H", fc_val) + struct.pack("<H", 0) + _mac("aa:aa:aa:aa:aa:aa")
        data = _build_radiotap() + frame
        packet = parse_80211_frame(data, interface="wlan0mon")
        self.assertEqual(packet["proto"], "wifi-ctrl")

    def test_truncated_frame_returns_none(self):
        data = _build_radiotap() + b"\x00\x00"
        packet = parse_80211_frame(data, interface="wlan0mon")
        self.assertIsNone(packet)

    def test_addr4_wds_data_frame_does_not_crash(self):
        fc_val = (0 << 4) | (2 << 2) | 0
        fc_val |= 0x0100 | 0x0200  # to_ds + from_ds
        frame = struct.pack("<H", fc_val) + struct.pack("<H", 0)
        frame += _mac("aa:aa:aa:aa:aa:aa") + _mac("bb:bb:bb:bb:bb:bb") + _mac("cc:cc:cc:cc:cc:cc")
        frame += struct.pack("<H", 0)
        frame += _mac("dd:dd:dd:dd:dd:dd")  # addr4
        data = _build_radiotap() + frame + b"\x00\x00\x00\x00"
        packet = parse_80211_frame(data, interface="wlan0mon")
        self.assertEqual(packet["proto"], "wifi-data")


if __name__ == "__main__":
    unittest.main()
