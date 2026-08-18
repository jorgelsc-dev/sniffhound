from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock

from sniffhound.monitors import DEFAULT_MONITORS, describe_match, evaluate_packet, normalize_monitor
from sniffhound.sniffer import Sniffer
from sniffhound.store import SniffStore


def _packet(**overrides) -> dict:
    base = {
        "proto": "tcp",
        "ip_version": 4,
        "eth_type": 0x0800,
        "src_ip": "10.0.0.5",
        "dst_ip": "10.0.0.1",
        "src_port": 51234,
        "dst_port": 80,
        "length": 60,
        "payload_len": 20,
        "payload_text": "",
        "payload_hex": "",
        "summary": "",
        "eth_src": "",
        "eth_dst": "",
    }
    base.update(overrides)
    return base


class TestNormalizeMonitor(unittest.TestCase):
    def test_rejects_empty_match(self):
        with self.assertRaises(ValueError):
            normalize_monitor({"id": "empty", "name": "Empty", "match": {}})

    def test_rejects_invalid_regex(self):
        with self.assertRaises(ValueError):
            normalize_monitor(
                {"id": "bad-regex", "name": "Bad regex", "match": {"payload_regex": ["("]}}
            )

    def test_accepts_rule_mode(self):
        monitor = normalize_monitor(
            {"id": "custom-ports", "name": "Custom ports", "match": {"ports": [4444]}}
        )
        self.assertEqual(monitor["mode"], "rule")
        self.assertEqual(monitor["match"]["ports"], [4444])

    def test_accepts_regex_mode(self):
        monitor = normalize_monitor(
            {"id": "custom-regex", "name": "Custom regex", "match": {"payload_regex": ["token=\\w+"]}}
        )
        self.assertEqual(monitor["mode"], "regex")

    def test_builtin_monitors_normalize_cleanly(self):
        for raw in DEFAULT_MONITORS:
            normalized = normalize_monitor(raw, allow_source=True)
            self.assertEqual(normalized["source"], "builtin")

    def test_stateful_mode_is_preserved(self):
        # Regression test: normalize_monitor used to only whitelist
        # {"rule", "regex"} and would silently coerce any other mode value to
        # "rule" — which would have destroyed "stateful" on every load,
        # breaking evaluate_packet()'s ability to skip these monitors so
        # anomaly.AnomalyEngine can drive them instead.
        stateful_ids = {
            raw["id"] for raw in DEFAULT_MONITORS if raw.get("mode") == "stateful"
        }
        self.assertTrue(stateful_ids, "expected at least one stateful builtin monitor")
        for raw in DEFAULT_MONITORS:
            if raw["id"] in stateful_ids:
                normalized = normalize_monitor(raw, allow_source=True)
                self.assertEqual(normalized["mode"], "stateful")


class TestEvaluatePacket(unittest.TestCase):
    def setUp(self):
        self.monitors = [normalize_monitor(item, allow_source=True) for item in DEFAULT_MONITORS]

    def test_credentials_regex_matches(self):
        packet = _packet(payload_text="POST /login HTTP/1.1\r\nusername=admin&password=hunter2")
        hits = evaluate_packet(packet, self.monitors)
        tags = {hit["tag"] for hit in hits}
        self.assertIn("credentials", tags)

    def test_admin_port_matches(self):
        packet = _packet(proto="tcp", dst_port=3389, src_port=51000)
        hits = evaluate_packet(packet, self.monitors)
        tags = {hit["tag"] for hit in hits}
        self.assertIn("admin-port", tags)

    def test_arp_l2_discovery_matches(self):
        packet = _packet(proto="arp", eth_type=0x0806, ip_version=0, src_port=0, dst_port=0)
        hits = evaluate_packet(packet, self.monitors)
        tags = {hit["tag"] for hit in hits}
        self.assertIn("discovery", tags)

    def test_plain_traffic_does_not_match(self):
        packet = _packet(dst_port=443, payload_text="", payload_hex="")
        hits = evaluate_packet(packet, self.monitors)
        self.assertEqual(hits, [])

    def test_stateful_monitors_are_never_matched_declaratively(self):
        # Stateful monitors have no declarative match logic — evaluate_packet
        # must skip them entirely (they're handled by anomaly.AnomalyEngine),
        # even though their `match` dict happens to overlap with this packet.
        packet = _packet(proto="arp", eth_type=0x0806, ip_version=0, src_port=0, dst_port=0)
        hits = evaluate_packet(packet, self.monitors)
        monitor_ids = {hit["monitor_id"] for hit in hits}
        self.assertNotIn("builtin-arp-spoof", monitor_ids)

    def test_bad_regex_in_saved_monitor_does_not_crash_evaluation(self):
        broken = dict(self.monitors[0])
        broken["match"] = dict(broken["match"])
        # Bypass normalize_monitor's validation to simulate a corrupted row.
        broken["match"]["payload_regex"] = ["("]
        hits = evaluate_packet(_packet(payload_text="anything"), [broken])
        self.assertEqual(hits, [])


class TestDescribeMatch(unittest.TestCase):
    def setUp(self):
        self.monitors = {
            item["id"]: item for item in (normalize_monitor(entry, allow_source=True) for entry in DEFAULT_MONITORS)
        }

    def test_regex_monitor_returns_matched_substring(self):
        monitor = self.monitors["builtin-credentials"]
        packet = _packet(payload_text="POST /login HTTP/1.1\r\nusername=admin&password=hunter2")
        value = describe_match(monitor, packet)
        self.assertIn("password", value.lower())

    def test_rule_monitor_returns_matched_port(self):
        monitor = self.monitors["builtin-admin-ports"]
        packet = _packet(dst_port=3389)
        self.assertEqual(describe_match(monitor, packet), "port 3389")

    def test_domain_takes_priority_when_present(self):
        monitor = self.monitors["builtin-dns-domains"]
        packet = _packet(proto="udp", dst_port=53, domain="example.com", domain_source="dns")
        self.assertEqual(describe_match(monitor, packet), "example.com")

    def test_arp_monitor_returns_eth_type(self):
        monitor = self.monitors["builtin-l2-discovery"]
        packet = _packet(proto="arp", eth_type=0x0806)
        self.assertEqual(describe_match(monitor, packet), "eth 0x0806")


class TestStoreMonitors(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test.db"
        self.store = SniffStore(self.db_path)

    def tearDown(self):
        self.store.close()
        self.temp_dir.cleanup()

    def test_builtin_monitors_are_seeded(self):
        monitors = self.store.list_monitors()
        ids = {row["id"] for row in monitors}
        self.assertIn("builtin-credentials", ids)
        self.assertIn("builtin-arp-spoof", ids)
        self.assertTrue(all(row["source"] == "builtin" for row in monitors))

    def test_new_builtin_monitors_reach_an_already_populated_db_without_touching_custom_rows(self):
        # Regression test for _seed_new_builtin_monitors(): simulate an
        # "old" DB that predates the new builtins (and already has a
        # user's own custom monitor), then reopen the store and confirm
        # the new builtins get added by id and nothing existing is touched.
        self.store.save_monitor(
            {"id": "custom-1", "name": "My custom monitor", "match": {"ports": [9999]}}
        )
        new_ids = [row["id"] for row in DEFAULT_MONITORS if row.get("mode") == "stateful"]
        self.assertTrue(new_ids)
        with self.store._lock:
            for monitor_id in new_ids:
                self.store._conn.execute("DELETE FROM monitors WHERE id = ?", (monitor_id,))
            self.store._conn.commit()
        remaining_ids = {row["id"] for row in self.store.list_monitors()}
        self.assertFalse(remaining_ids.intersection(new_ids))
        self.assertIn("custom-1", remaining_ids)

        reopened = SniffStore(self.db_path)
        try:
            ids_after = {row["id"] for row in reopened.list_monitors()}
        finally:
            reopened.close()
        self.assertTrue(set(new_ids).issubset(ids_after))
        self.assertIn("custom-1", ids_after)

    def test_save_list_delete_custom_monitor(self):
        saved = self.store.save_monitor(
            {"id": "custom-1", "name": "My monitor", "match": {"ports": [9999]}}
        )
        self.assertEqual(saved["source"], "custom")
        ids = {row["id"] for row in self.store.list_monitors()}
        self.assertIn("custom-1", ids)
        self.store.delete_monitor("custom-1")
        ids = {row["id"] for row in self.store.list_monitors()}
        self.assertNotIn("custom-1", ids)

    def test_builtin_monitor_is_read_only(self):
        with self.assertRaises(ValueError):
            self.store.save_monitor({"id": "builtin-credentials", "name": "Hacked"})
        with self.assertRaises(ValueError):
            self.store.delete_monitor("builtin-credentials")

    def test_monitor_filter_toggle_defaults_and_persists(self):
        self.assertTrue(self.store.get_monitor_filter_enabled())
        self.store.set_monitor_filter_enabled(False)
        self.assertFalse(self.store.get_monitor_filter_enabled())


class TestSnifferGatedPersistence(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test.db"
        self.store = SniffStore(self.db_path)
        self.sniffer = Sniffer(self.store, MagicMock(), interfaces=())

    def tearDown(self):
        self.store.close()
        self.temp_dir.cleanup()

    def _base_packet(self, **overrides) -> dict:
        packet = {
            "session_id": 0,
            "interface": "test0",
            "eth_src": "",
            "eth_dst": "",
            "eth_type": 0x0800,
            "ip_version": 4,
            "src_ip": "10.0.0.5",
            "dst_ip": "10.0.0.9",
            "proto": "tcp",
            "src_port": 51234,
            "dst_port": 8081,
            "ttl": 64,
            "hop_limit": 0,
            "length": 60,
            "payload_len": 10,
            "state": "open",
            "scan_state": "active",
            "tcp_flags": "",
            "icmp_type": 0,
            "icmp_code": 0,
            "arp_opcode": 0,
            "summary": "",
            "payload_text": "",
            "payload_hex": "",
            "banner_text": "",
            "raw_packet": b"",
        }
        packet.update(overrides)
        return packet

    def test_undetected_packet_is_not_persisted(self):
        self.sniffer._store_packet(self._base_packet())
        self.assertEqual(self.store.list_count("packets"), 0)
        self.assertEqual(self.sniffer.state.packets_seen, 1)
        self.assertEqual(self.sniffer.state.packets_stored, 0)

    def test_detected_packet_is_persisted(self):
        self.sniffer._store_packet(self._base_packet(dst_port=3389))
        self.assertEqual(self.store.list_count("packets"), 1)
        self.assertEqual(self.sniffer.state.packets_stored, 1)

    def test_filter_disabled_persists_everything(self):
        self.store.set_monitor_filter_enabled(False)
        self.sniffer._store_packet(self._base_packet())
        self.assertEqual(self.store.list_count("packets"), 1)
        self.assertEqual(self.sniffer.state.packets_stored, 1)

    def test_undetected_packets_are_time_throttled_on_the_websocket(self):
        self.sniffer._store_packet(self._base_packet())
        self.assertEqual(self.sniffer.hub.broadcast.call_count, 1)
        broadcast_type = self.sniffer.hub.broadcast.call_args[0][0]["type"]
        self.assertEqual(broadcast_type, "stats_update")
        for _ in range(200):
            self.sniffer._store_packet(self._base_packet())
        # Still within the same throttle window, so wire-speed traffic can't flood the socket.
        self.assertEqual(self.sniffer.hub.broadcast.call_count, 1)

    def test_detected_packet_always_broadcasts_full_packet_event(self):
        self.sniffer._store_packet(self._base_packet(dst_port=3389))
        types = [call.args[0]["type"] for call in self.sniffer.hub.broadcast.call_args_list]
        self.assertEqual(types, ["packet", "stats_update"])

    def test_detected_packet_broadcast_includes_severity_on_monitor_tag(self):
        # Frontend notifications decide what's "important" from this field -
        # it has to ride along on the WS "packet" event, not just live in
        # the monitor definition server-side.
        self.sniffer._store_packet(self._base_packet(dst_port=3389))
        packet_call = next(
            call for call in self.sniffer.hub.broadcast.call_args_list if call.args[0]["type"] == "packet"
        )
        broadcast_packet = packet_call.args[0]["packet"]
        tags = json.loads(broadcast_packet["tags_json"])
        monitor_tags = [tag for tag in tags if tag.get("key") == "monitor"]
        self.assertTrue(monitor_tags)
        self.assertEqual(monitor_tags[0]["severity"], "medium")

    def test_detected_packet_is_queryable_by_monitor_id(self):
        self.sniffer._store_packet(self._base_packet(dst_port=3389))
        rows = self.store.list_packets_by_monitor("builtin-admin-ports")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["dst_port"], 3389)
        self.assertEqual(self.store.list_packets_by_monitor("builtin-credentials"), [])

    def test_list_packets_by_monitor_includes_matched_value(self):
        self.sniffer._store_packet(self._base_packet(dst_port=3389))
        rows = self.store.list_packets_by_monitor("builtin-admin-ports")
        self.assertEqual(rows[0]["matched_value"], "port 3389")

    def test_list_packets_by_monitor_search_filters(self):
        self.sniffer._store_packet(self._base_packet(dst_port=3389, dst_ip="10.0.0.50"))
        self.sniffer._store_packet(self._base_packet(dst_port=3389, dst_ip="10.0.0.99"))
        rows = self.store.list_packets_by_monitor("builtin-admin-ports", search="10.0.0.50")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["dst_ip"], "10.0.0.50")


if __name__ == "__main__":
    unittest.main()
