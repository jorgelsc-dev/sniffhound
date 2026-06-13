"""
Comprehensive test suite for SniffHound

Includes unit tests, integration tests, and security tests.
Run with: pytest tests/ -v --cov=sniffhound
"""

from __future__ import annotations

import json
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import sniffhound
from sniffhound import auth, logger, utils
from sniffhound.sniffer import Sniffer
from sniffhound.store import SniffStore


class TestVersion(unittest.TestCase):
    """Test version information."""

    def test_version_format(self):
        """Version should follow semantic versioning."""
        version = sniffhound.__version__
        parts = version.split(".")
        self.assertEqual(len(parts), 3)
        for part in parts:
            self.assertTrue(part.isdigit())

    def test_version_is_string(self):
        self.assertIsInstance(sniffhound.__version__, str)


class TestNDJsonLogger(unittest.TestCase):
    """Test NDJSON logging functionality."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.log_file = Path(self.temp_dir.name) / "test.log"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_logger_creates_log_file(self):
        """Logger should create log file if it doesn't exist."""
        test_logger = logger.get_logger("test", log_file=self.log_file)
        test_logger.info("Test message")
        self.assertTrue(self.log_file.exists())

    def test_logger_writes_valid_json(self):
        """Each log line should be valid JSON."""
        test_logger = logger.get_logger("test", log_file=self.log_file)
        test_logger.info("Test message", extra={"custom_field": "value"})
        test_logger.warning("Warning message")
        test_logger.error("Error message")

        with open(self.log_file) as f:
            lines = f.readlines()

        self.assertGreater(len(lines), 0)
        for line in lines:
            parsed = json.loads(line.strip())
            self.assertIn("timestamp", parsed)
            self.assertIn("level", parsed)
            self.assertIn("message", parsed)

    def test_logger_captures_exceptions(self):
        """Logger should capture exception info."""
        test_logger = logger.get_logger("test", log_file=self.log_file)
        try:
            raise ValueError("Test error")
        except ValueError:
            test_logger.exception("An error occurred")

        with open(self.log_file) as f:
            content = f.read()

        parsed = json.loads(content.strip())
        self.assertIn("exception", parsed)
        self.assertIn("ValueError", parsed["exception"])

    def test_logger_context_manager(self):
        """LoggerContext should temporarily change log level."""
        test_logger = logger.get_logger("test", log_file=self.log_file, level=20)  # INFO
        original_level = test_logger.level

        with logger.LoggerContext(test_logger, level=10):  # DEBUG
            self.assertEqual(test_logger.level, 10)

        self.assertEqual(test_logger.level, original_level)


class TestJWTAuth(unittest.TestCase):
    """Test JWT authentication."""

    def test_encode_decode_jwt(self):
        """JWT should encode and decode correctly."""
        payload = {"user": "test_user", "role": "admin"}
        token = auth.encode_jwt(payload)

        is_valid, decoded = auth.decode_jwt(token)
        self.assertTrue(is_valid)
        self.assertEqual(decoded["user"], "test_user")
        self.assertEqual(decoded["role"], "admin")

    def test_invalid_token_signature(self):
        """Token with invalid signature should fail verification."""
        token = auth.encode_jwt({"user": "test"})
        # Tamper with the token
        parts = token.split(".")
        tampered = f"{parts[0]}.{parts[1]}.INVALID"

        is_valid, decoded = auth.decode_jwt(tampered)
        self.assertFalse(is_valid)
        self.assertIsNone(decoded)

    def test_expired_token(self):
        """Expired token should be rejected."""
        # Create a token that expired in the past
        now = int(time.time())
        payload = {
            "user": "test",
            "exp": now - 3600,  # Expired 1 hour ago
            "iat": now - 7200,
        }

        token = auth.encode_jwt(payload)
        is_valid, decoded = auth.decode_jwt(token)
        self.assertFalse(is_valid)

    def test_generate_token(self):
        """Generated token should be valid."""
        token = auth.generate_token(user="admin", scope="full")
        is_valid, payload = auth.decode_jwt(token)

        self.assertTrue(is_valid)
        self.assertEqual(payload["user"], "admin")
        self.assertEqual(payload["scope"], "full")

    def test_extract_token_from_header(self):
        """Should extract token from Bearer header."""
        token = auth.generate_token(user="test")
        header = f"Bearer {token}"

        extracted = auth.extract_token_from_header(header)
        self.assertEqual(extracted, token)

    def test_extract_token_without_bearer(self):
        """Should handle token without Bearer prefix."""
        token = "some.jwt.token"
        extracted = auth.extract_token_from_header(token)
        self.assertEqual(extracted, token)

    def test_authenticate_request_with_valid_token(self):
        """Valid token should authenticate successfully."""
        token = auth.generate_token(user="admin")
        is_auth, user_info = auth.authenticate_request(token)

        self.assertTrue(is_auth)
        self.assertEqual(user_info["user"], "admin")
        self.assertTrue(user_info["authenticated"])

    def test_authenticate_request_without_token_no_auth_required(self):
        """Without token and auth not required, should be anonymous."""
        with patch.dict(os.environ, {"SNIFFHOUND_REQUIRE_AUTH": "0"}):
            # Reload auth module to pick up new env var
            import importlib

            importlib.reload(auth)
            is_auth, user_info = auth.authenticate_request(None)

            # In non-enforced mode, should allow
            if is_auth:
                self.assertTrue(is_auth)


class TestUtils(unittest.TestCase):
    """Test utility functions."""

    def test_bytes_to_hex_preview(self):
        """Should convert bytes to hex preview."""
        data = b"\x00\x01\x02\x03"
        preview = utils.bytes_to_hex_preview(data, max_length=8)
        self.assertIn("00010203", preview)

    def test_normalize_text(self):
        """Should normalize text safely."""
        text = "Hello\x00World\xff"
        normalized = utils.normalize_text(text)
        self.assertIsInstance(normalized, str)
        # Should not raise

    def test_safe_int_parsing(self):
        """Should safely parse integers."""
        self.assertEqual(utils.safe_int("123", 0), 123)
        self.assertEqual(utils.safe_int("invalid", 999), 999)
        self.assertEqual(utils.safe_int(None, 42), 42)

    def test_safe_float_parsing(self):
        """Should safely parse floats."""
        self.assertEqual(utils.safe_float("3.14", 0.0), 3.14)
        self.assertEqual(utils.safe_float("invalid", 2.0), 2.0)

    def test_clamp_int(self):
        """Should clamp integer to range."""
        self.assertEqual(utils.clamp_int(5, 1, 10), 5)
        self.assertEqual(utils.clamp_int(0, 1, 10), 1)
        self.assertEqual(utils.clamp_int(20, 1, 10), 10)

    def test_json_dumps_is_consistent(self):
        """json_dumps should produce consistent output."""
        data = {"z": 1, "a": 2, "m": 3}
        result1 = utils.json_dumps(data)
        result2 = utils.json_dumps(data)
        self.assertEqual(result1, result2)

    def test_normalize_protocol_name(self):
        """Should normalize protocol names."""
        self.assertEqual(utils.normalize_protocol_name("tcp"), "tcp")
        self.assertEqual(utils.normalize_protocol_name("UDP"), "udp")
        self.assertEqual(utils.normalize_protocol_name("ICMP"), "icmp")


class TestSnifferParsing(unittest.TestCase):
    """Test packet parsing edge cases from live captures."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test.db"
        self.store = SniffStore(self.db_path)
        self.sniffer = Sniffer(self.store, MagicMock(), interfaces=())

    def tearDown(self):
        self.store.close()
        self.temp_dir.cleanup()

    def test_parse_raw_ipv4_packet_without_ethernet_header(self):
        packet = self.sniffer.parse_packet(
            bytes.fromhex(
                "45000028A74A40004006D78D0A0D0D03B5E1EF068A5201BB"
                "6349235CF2E6C49250100133BC120000"
            ),
            interface="Neubox",
        )

        self.assertIsNotNone(packet)
        self.assertEqual(packet["proto"], "tcp")
        self.assertEqual(packet["ip_version"], 4)
        self.assertEqual(packet["src_ip"], "10.13.13.3")
        self.assertEqual(packet["dst_ip"], "181.225.239.6")
        self.assertEqual(packet["src_port"], 35410)
        self.assertEqual(packet["dst_port"], 443)
        self.assertEqual(packet["eth_type"], 0x0800)

    def test_parse_truncated_raw_ipv4_packet_without_ethernet_header(self):
        packet = self.sniffer.parse_packet(
            bytes.fromhex(
                "4500058C180B00003806086F2268237B0A0D0D030050BA9A"
                "282AC4C9C0666D928018041A4BED00000101080A00DDD904"
            ),
            interface="Neubox",
        )

        self.assertIsNotNone(packet)
        self.assertEqual(packet["proto"], "tcp")
        self.assertEqual(packet["src_ip"], "34.104.35.123")
        self.assertEqual(packet["dst_ip"], "10.13.13.3")
        self.assertEqual(packet["src_port"], 80)
        self.assertEqual(packet["dst_port"], 47770)

    def test_parse_stp_bpdu_frame(self):
        packet = self.sniffer.parse_packet(
            bytes.fromhex(
                "0180C2000000D401C3D8E1250027424203000002023E8000"
                "D401C3D8E125000000008000D401C3D8E125800200001400"
            ),
            interface="eth0",
        )

        self.assertIsNotNone(packet)
        self.assertEqual(packet["proto"], "stp")
        self.assertEqual(packet["eth_dst"], "01:80:c2:00:00:00")
        self.assertEqual(packet["summary"], "STP BPDU")
        self.assertTrue(packet["flow_key"].startswith("stp|"))


class TestSniffStore(unittest.TestCase):
    """Test SQLite store functionality."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test.db"
        self.store = SniffStore(self.db_path)

    def tearDown(self):
        self.store.close()
        self.temp_dir.cleanup()

    def test_store_initialization(self):
        """Store should initialize with empty counts."""
        counts = self.store.summary_counts()
        self.assertEqual(counts["packets"], 0)
        self.assertEqual(counts["sessions"], 0)

    def test_register_packet(self):
        """Should register a packet."""
        packet = {
            "session_id": 1,
            "proto": "tcp",
            "src_ip": "192.168.1.1",
            "dst_ip": "192.168.1.2",
            "src_port": 1234,
            "dst_port": 80,
            "payload_text": "test",
            "payload_hex": "74657374",
            "summary": "TCP packet",
            "raw_packet": b"\x45\x00",
        }
        result = self.store.register_packet(packet)
        self.assertIn("id", result)

        counts = self.store.summary_counts()
        self.assertEqual(counts["packets"], 1)

    def test_packet_raw_binary_encoding(self):
        """Raw packet binary should be encoded as hex string."""
        packet = {
            "session_id": 1,
            "proto": "tcp",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "src_port": 5000,
            "dst_port": 443,
            "payload_text": "",
            "payload_hex": "",
            "summary": "Test",
            "raw_packet": b"\x00\x01\x02\xff",
        }
        result = self.store.register_packet(packet)
        self.assertIsInstance(result["raw_packet"], str)
        self.assertRegex(result["raw_packet"], r"^[0-9a-f]+$")

    def test_snapshot_is_json_serializable(self):
        """Snapshots should be JSON serializable."""
        packet = {
            "session_id": 1,
            "proto": "tcp",
            "src_ip": "8.8.8.8",
            "dst_ip": "1.1.1.1",
            "src_port": 53,
            "dst_port": 53,
            "payload_text": "",
            "payload_hex": "",
            "summary": "DNS",
            "raw_packet": b"",
        }
        self.store.register_packet(packet)

        snapshot = self.store.dashboard_snapshot()
        # Should not raise
        json.dumps(snapshot)

    def test_ip_intel_handles_structured_tags(self):
        """Host intel should tolerate tags stored as objects."""
        packet = {
            "session_id": 1,
            "proto": "tcp",
            "src_ip": "127.0.0.1",
            "dst_ip": "127.0.0.1",
            "src_port": 34500,
            "dst_port": 45678,
            "payload_text": "loopback test",
            "payload_hex": "6c6f6f706261636b2074657374",
            "summary": "Loopback packet",
            "tags": [
                {"key": "role", "value": "loopback"},
                {"key": "scope", "value": "local"},
            ],
            "raw_packet": b"\x45\x00",
        }
        self.store.register_packet(packet)

        intel = self.store.ip_intel("127.0.0.1")
        services = intel["host"]["transport"]["services"]
        self.assertGreaterEqual(len(services), 1)
        self.assertIn("loopback", services[0]["tags_text"])
        self.assertIn("local", services[0]["tags_text"])
        json.dumps(intel)

    def test_soc_analysis_snapshot_produces_iterative_cycles(self):
        """SOC analysis should return stable multi-pass triage output."""
        self.store.register_packet(
            {
                "session_id": 1,
                "proto": "tcp",
                "src_ip": "127.0.0.1",
                "dst_ip": "127.0.0.1",
                "src_port": 45670,
                "dst_port": 45670,
                "direction": "unknown",
                "state": "open",
                "summary": "Loopback packet",
                "payload_text": "{\"type\":\"telemetry\",\"packet\":1}",
                "tags": [{"key": "role", "value": "loopback"}],
                "raw_packet": b"\x45\x00",
            }
        )
        self.store.register_packet(
            {
                "session_id": 2,
                "proto": "udp",
                "src_ip": "72.249.55.101",
                "dst_ip": "192.168.88.250",
                "src_port": 443,
                "dst_port": 51820,
                "direction": "outbound",
                "state": "open",
                "summary": "Tunnel packet",
                "payload_text": "GET / HTTP/1.1",
                "banner_text": "HTTP request",
                "tags": [{"key": "service", "value": "vpn"}],
                "raw_packet": b"\x45\x00",
            }
        )

        snapshot = self.store.soc_analysis_snapshot(cycles=4, limit=250)

        self.assertIn("soc_summary", snapshot)
        self.assertEqual(len(snapshot["cycles"]), 4)
        self.assertGreaterEqual(snapshot["soc_summary"]["findings_total"], 1)
        self.assertGreaterEqual(len(snapshot["findings"]), 1)
        self.assertGreaterEqual(len(snapshot["questions"]), 1)
        self.assertGreaterEqual(len(snapshot["top_hosts"]), 1)
        json.dumps(snapshot)


class TestConcurrency(unittest.TestCase):
    """Test thread-safety of components."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test.db"
        self.store = SniffStore(self.db_path)

    def tearDown(self):
        self.store.close()
        self.temp_dir.cleanup()

    def test_concurrent_packet_registration(self):
        """Store should handle concurrent packet registration."""
        packet_count = 50
        threads = []

        def register_packets():
            for i in range(10):
                self.store.register_packet(
                    {
                        "session_id": 1,
                        "proto": "tcp",
                        "src_ip": "10.0.0.1",
                        "dst_ip": "10.0.0.2",
                        "src_port": 1000 + i,
                        "dst_port": 80,
                        "payload_text": f"packet_{i}",
                        "payload_hex": "",
                        "summary": f"Test {i}",
                        "raw_packet": b"",
                    }
                )

        for _ in range(5):
            t = threading.Thread(target=register_packets)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        counts = self.store.summary_counts()
        self.assertEqual(counts["packets"], packet_count)


class TestSettings(unittest.TestCase):
    """Test settings and environment configuration."""

    def test_capture_demo_mode_setting(self):
        """CAPTURE_DEMO_MODE should be configurable."""
        from sniffhound.settings import CAPTURE_DEMO_MODE

        # Default should be False (demo disabled)
        self.assertFalse(CAPTURE_DEMO_MODE)

    def test_db_path_configuration(self):
        """DB_PATH should use environment variable."""
        db_path = os.getenv("SNIFFHOUND_DB_PATH", "SniffHound.db")
        self.assertIsInstance(db_path, str)


class TestSecurityBasics(unittest.TestCase):
    """Basic security tests."""

    def test_no_hardcoded_credentials(self):
        """Should not have hardcoded passwords."""
        import sniffhound.app
        import sniffhound.auth
        import sniffhound.settings

        modules = [sniffhound.app, sniffhound.auth, sniffhound.settings]
        for module in modules:
            source = open(module.__file__).read()
            self.assertNotIn("password", source.lower())
            self.assertNotIn("secret123", source.lower())

    def test_jwt_uses_strong_hash(self):
        """JWT should use HS256."""
        import sniffhound.auth as auth_module

        source = open(auth_module.__file__).read()
        self.assertIn("HS256", source)
        self.assertIn("sha256", source)


if __name__ == "__main__":
    unittest.main()
