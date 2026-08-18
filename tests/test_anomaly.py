from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from sniffhound.anomaly import (
    AnomalyEngine,
    ArpSpoofDetector,
    IcmpFloodDetector,
    WifiDeauthFloodDetector,
    WifiRogueApDetector,
)
from sniffhound.monitors import DEFAULT_MONITORS, normalize_monitor
from sniffhound.sniffer import Sniffer, build_base_packet
from sniffhound.store import SniffStore


def _monitors():
    return [normalize_monitor(item, allow_source=True) for item in DEFAULT_MONITORS]


class TestArpSpoofDetector(unittest.TestCase):
    def test_first_sighting_establishes_baseline(self):
        detector = ArpSpoofDetector()
        hit = detector.evaluate({"proto": "arp", "arp_opcode": 2, "src_ip": "10.0.0.5", "eth_src": "aa:aa:aa:aa:aa:aa"})
        self.assertIsNone(hit)

    def test_conflicting_mac_flags(self):
        detector = ArpSpoofDetector()
        detector.evaluate({"proto": "arp", "arp_opcode": 2, "src_ip": "10.0.0.5", "eth_src": "aa:aa:aa:aa:aa:aa"})
        hit = detector.evaluate({"proto": "arp", "arp_opcode": 2, "src_ip": "10.0.0.5", "eth_src": "bb:bb:bb:bb:bb:bb"})
        self.assertIsNotNone(hit)
        self.assertIn("10.0.0.5", hit["detail"])

    def test_ignores_non_arp_and_requests(self):
        detector = ArpSpoofDetector()
        self.assertIsNone(detector.evaluate({"proto": "tcp"}))
        self.assertIsNone(detector.evaluate({"proto": "arp", "arp_opcode": 1, "src_ip": "10.0.0.5", "eth_src": "aa:aa:aa:aa:aa:aa"}))

    def test_same_mac_is_not_a_conflict(self):
        detector = ArpSpoofDetector()
        pkt = {"proto": "arp", "arp_opcode": 2, "src_ip": "10.0.0.5", "eth_src": "aa:aa:aa:aa:aa:aa"}
        detector.evaluate(pkt)
        self.assertIsNone(detector.evaluate(pkt))


class TestIcmpFloodDetector(unittest.TestCase):
    def test_fires_once_threshold_crossed(self):
        detector = IcmpFloodDetector()
        detector._threshold = 5
        hits = [detector.evaluate({"proto": "icmp", "src_ip": "9.9.9.9"}) for _ in range(5)]
        self.assertTrue(any(hits))
        self.assertEqual(sum(1 for hit in hits if hit), 1)

    def test_ignores_non_icmp(self):
        detector = IcmpFloodDetector()
        self.assertIsNone(detector.evaluate({"proto": "tcp", "src_ip": "9.9.9.9"}))


class TestWifiDeauthFloodDetector(unittest.TestCase):
    def test_fires_on_burst(self):
        detector = WifiDeauthFloodDetector()
        detector._threshold = 4
        pkt = {"proto": "wifi-mgmt", "wifi_subtype": "deauth", "wifi_bssid": "aa:bb:cc:dd:ee:ff"}
        hits = [detector.evaluate(pkt) for _ in range(4)]
        self.assertTrue(any(hits))

    def test_ignores_beacons(self):
        detector = WifiDeauthFloodDetector()
        self.assertIsNone(detector.evaluate({"proto": "wifi-mgmt", "wifi_subtype": "beacon"}))


class TestWifiRogueApDetector(unittest.TestCase):
    def test_single_bssid_is_fine(self):
        detector = WifiRogueApDetector()
        pkt = {"proto": "wifi-mgmt", "wifi_subtype": "beacon", "wifi_ssid": "FreeWifi", "wifi_bssid": "11:11:11:11:11:11"}
        self.assertIsNone(detector.evaluate(pkt))
        self.assertIsNone(detector.evaluate(pkt))

    def test_second_bssid_for_same_ssid_flags(self):
        detector = WifiRogueApDetector()
        detector.evaluate({"proto": "wifi-mgmt", "wifi_subtype": "beacon", "wifi_ssid": "FreeWifi", "wifi_bssid": "11:11:11:11:11:11"})
        hit = detector.evaluate({"proto": "wifi-mgmt", "wifi_subtype": "beacon", "wifi_ssid": "FreeWifi", "wifi_bssid": "22:22:22:22:22:22"})
        self.assertIsNotNone(hit)
        self.assertIn("FreeWifi", hit["detail"])


class TestAnomalyEngine(unittest.TestCase):
    def test_disabled_stateful_monitor_is_not_evaluated(self):
        engine = AnomalyEngine()
        monitors = _monitors()
        for monitor in monitors:
            if monitor["id"] == "builtin-arp-spoof":
                monitor["enabled"] = False
        engine.evaluate({"proto": "arp", "arp_opcode": 2, "src_ip": "1.1.1.1", "eth_src": "aa:aa:aa:aa:aa:aa"}, monitors)
        hits = engine.evaluate({"proto": "arp", "arp_opcode": 2, "src_ip": "1.1.1.1", "eth_src": "bb:bb:bb:bb:bb:bb"}, monitors)
        self.assertEqual(hits, [])

    def test_missing_monitor_definition_is_skipped(self):
        engine = AnomalyEngine()
        hits = engine.evaluate({"proto": "arp", "arp_opcode": 2, "src_ip": "1.1.1.1", "eth_src": "aa:aa:aa:aa:aa:aa"}, [])
        self.assertEqual(hits, [])

    def test_hit_shape_matches_evaluate_packet_output(self):
        engine = AnomalyEngine()
        monitors = _monitors()
        engine.evaluate({"proto": "arp", "arp_opcode": 2, "src_ip": "1.1.1.1", "eth_src": "aa:aa:aa:aa:aa:aa"}, monitors)
        hits = engine.evaluate({"proto": "arp", "arp_opcode": 2, "src_ip": "1.1.1.1", "eth_src": "bb:bb:bb:bb:bb:bb"}, monitors)
        self.assertEqual(len(hits), 1)
        hit = hits[0]
        for key in ("monitor_id", "monitor_name", "tag", "label", "severity"):
            self.assertIn(key, hit)
        self.assertEqual(hit["monitor_id"], "builtin-arp-spoof")
        self.assertEqual(hit["severity"], "critical")


class TestSnifferAnomalyIntegration(unittest.TestCase):
    """Verifies the Sniffer._store_packet restructuring: anomaly hits must
    persist a packet even when the declarative monitor filter is on and no
    declarative monitor matched — this is the regression test for the
    "anomaly detectors must run unconditionally" fix."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test.db"
        self.store = SniffStore(self.db_path)
        self.sniffer = Sniffer(self.store, MagicMock(), interfaces=())

    def tearDown(self):
        self.store.close()
        self.temp_dir.cleanup()

    def _arp_packet(self, ip: str, mac: str) -> dict:
        packet = build_base_packet("now", "test0", b"\x00" * 28, b"\x00" * 28, eth_src=mac, eth_dst="ff:ff:ff:ff:ff:ff", eth_type=0x0806)
        packet.update(
            {
                "proto": "arp",
                "arp_opcode": 2,
                "src_ip": ip,
                "dst_ip": "10.0.0.1",
                "ip_version": 0,
                "flow_key": f"arp:{ip}",
                "summary": f"ARP {ip}",
            }
        )
        return packet

    def test_arp_conflict_persists_despite_filter_enabled(self):
        self.assertTrue(self.store.get_monitor_filter_enabled())
        self.sniffer._store_packet(self._arp_packet("10.0.0.5", "aa:aa:aa:aa:aa:aa"))
        self.sniffer._store_packet(self._arp_packet("10.0.0.5", "bb:bb:bb:bb:bb:bb"))
        matched = self.store.list_packets_by_monitor("builtin-arp-spoof")
        self.assertTrue(matched, "expected the second, conflicting ARP packet to be tagged and persisted")


if __name__ == "__main__":
    unittest.main()
