from __future__ import annotations

import os
import socket
import tempfile
import unittest
from pathlib import Path
import json
import importlib
import io
from contextlib import redirect_stdout
from unittest.mock import patch

import sniffhound
from sniffhound.store import SniffStore
from wsbuilder.http import Request


def _reload_auth_stack(require_auth: str = "1"):
    previous = os.environ.get("SNIFFHOUND_REQUIRE_AUTH")
    os.environ["SNIFFHOUND_REQUIRE_AUTH"] = require_auth
    try:
        import sniffhound.auth as auth_module
        import sniffhound.app as app_module

        auth_module = importlib.reload(auth_module)
        app_module = importlib.reload(app_module)
        return auth_module, app_module
    finally:
        if previous is None:
            os.environ.pop("SNIFFHOUND_REQUIRE_AUTH", None)
        else:
            os.environ["SNIFFHOUND_REQUIRE_AUTH"] = previous


def _reload_runtime_stack(require_auth: str = "1"):
    previous = os.environ.get("SNIFFHOUND_REQUIRE_AUTH")
    os.environ["SNIFFHOUND_REQUIRE_AUTH"] = require_auth
    try:
        import sniffhound.settings as settings_module
        import sniffhound.auth as auth_module
        import sniffhound.app as app_module

        settings_module = importlib.reload(settings_module)
        auth_module = importlib.reload(auth_module)
        app_module = importlib.reload(app_module)
        return settings_module, auth_module, app_module
    finally:
        if previous is None:
            os.environ.pop("SNIFFHOUND_REQUIRE_AUTH", None)
        else:
            os.environ["SNIFFHOUND_REQUIRE_AUTH"] = previous


class SmokeTests(unittest.TestCase):
    def test_version(self):
        self.assertEqual(sniffhound.__version__, "0.1.0")

    def test_store_initializes_and_summaries_work(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "sniffhound.db"
            store = SniffStore(db_path)
            try:
                counts = store.summary_counts()
                self.assertIn("sessions", counts)
                self.assertIn("packets", counts)
                self.assertIn("unique_hosts", counts)
                self.assertGreaterEqual(counts["rulesets"], 1)
            finally:
                store.close()

    def test_rulesets_list_survives_tuple_rows(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "sniffhound.db"
            store = SniffStore(db_path)
            try:
                store._conn.row_factory = None
                rows = store.list_rulesets()
                self.assertGreaterEqual(len(rows), 1)
                self.assertIn("id", rows[0])
                self.assertIn("match", rows[0])
            finally:
                store.close()

    def test_rulesets_list_tolerates_invalid_utf8_description(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "sniffhound.db"
            store = SniffStore(db_path)
            try:
                now = "2026-06-11T00:00:00.000Z"
                store._conn.execute(
                    """
                    INSERT INTO rulesets
                    (id, name, description, enabled, priority, source, match_json, action_json, created_at, updated_at)
                    VALUES (?, ?, CAST(X'FF7754AABB' AS TEXT), ?, ?, ?, ?, ?, ?, ?)
                    """,
                    ("legacy-bad", "Legacy Bad", 1, 999, "custom", "{}", "{}", now, now),
                )
                store._conn.commit()

                rows = store.list_rulesets()
                row = next(item for item in rows if item["id"] == "legacy-bad")
                self.assertIsInstance(row["description"], str)
                self.assertIn("\ufffd", row["description"])
            finally:
                store.close()

    def test_raw_packet_is_json_safe(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "sniffhound.db"
            store = SniffStore(db_path)
            try:
                packet = {
                    "session_id": 1,
                    "proto": "tcp",
                    "src_ip": "192.0.2.10",
                    "dst_ip": "198.51.100.20",
                    "src_port": 12345,
                    "dst_port": 80,
                    "payload_text": "GET / HTTP/1.1",
                    "payload_hex": "474554202f20485454502f312e31",
                    "summary": "HTTP request",
                    "raw_packet": b"\x00\x01\x02\x03",
                }
                row = store.register_packet(packet)
                self.assertIsInstance(row["raw_packet"], str)
                json.dumps(store.dashboard_snapshot())
                json.dumps(store.analytics_snapshot())
            finally:
                store.close()

    def test_app_import_uses_configured_database(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "runtime.db"
            previous = os.environ.get("SNIFFHOUND_DB_PATH")
            os.environ["SNIFFHOUND_DB_PATH"] = str(db_path)
            try:
                import sniffhound.settings as settings_module
                import sniffhound.app as app_module

                importlib.reload(settings_module)
                app_module = importlib.reload(app_module)

                self.assertTrue(hasattr(app_module, "app"))
                self.assertTrue(db_path.exists())
                app_module.store.close()
            finally:
                if previous is None:
                    os.environ.pop("SNIFFHOUND_DB_PATH", None)
                else:
                    os.environ["SNIFFHOUND_DB_PATH"] = previous

    def test_frontend_build_is_served(self):
        import sniffhound.app as app_module

        response = app_module.root(None)

        payload = response.body if isinstance(response.body, (bytes, bytearray)) else response.status
        body = payload.decode("utf-8") if isinstance(payload, (bytes, bytearray)) else str(payload)
        self.assertIn('<div id="app"></div>', body)
        self.assertIn('/assets/index-', body)
        self.assertIn('type="module"', body)

    def test_session_token_is_eight_characters(self):
        import sniffhound.auth as auth_module

        previous_token = auth_module._SESSION_TOKEN
        try:
            auth_module._SESSION_TOKEN = None
            token = auth_module.initialize_session_token()
            self.assertEqual(len(token), auth_module.SESSION_TOKEN_LENGTH)
            self.assertRegex(token, r"^[A-Za-z0-9]{8}$")
        finally:
            auth_module._SESSION_TOKEN = previous_token

    def test_auth_session_endpoint_reports_auth_requirement(self):
        _auth_module, app_module = _reload_auth_stack("1")

        request = Request("GET", "/api/auth/session", "", {}, b"", ("127.0.0.1", 0))
        response = app_module.app.dispatch(request)
        payload = json.loads(response.body.decode("utf-8"))

        self.assertEqual(response.status, 200)
        self.assertTrue(payload["require_auth"])
        self.assertFalse(payload["authenticated"])

    def test_api_routes_return_401_without_token(self):
        _auth_module, app_module = _reload_auth_stack("1")

        request = Request("GET", "/api/hello", "", {}, b"", ("127.0.0.1", 0))
        response = app_module.app.dispatch(request)
        payload = json.loads(response.body.decode("utf-8"))

        self.assertEqual(response.status, 401)
        self.assertEqual(payload["code"], "auth_required")

    def test_api_routes_accept_valid_token(self):
        auth_module, app_module = _reload_auth_stack("1")

        previous_token = auth_module._SESSION_TOKEN
        try:
            auth_module._SESSION_TOKEN = "Ab12Cd34"
            request = Request(
                "GET",
                "/api/hello",
                "",
                {"authorization": "Bearer Ab12Cd34"},
                b"",
                ("127.0.0.1", 0),
            )
            response = app_module.app.dispatch(request)
            payload = json.loads(response.body.decode("utf-8"))
        finally:
            auth_module._SESSION_TOKEN = previous_token

        self.assertEqual(response.status, 200)
        self.assertEqual(payload["status"], "ok")

    def test_runtime_uses_configured_default_mode_on_startup(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "runtime.db"
            store = SniffStore(db_path)
            try:
                store.set_runtime_config("runtime_mode", "honeypot")
            finally:
                store.close()

            previous_db = os.environ.get("SNIFFHOUND_DB_PATH")
            previous_mode = os.environ.get("SNIFFHOUND_RUNTIME_MODE")
            os.environ["SNIFFHOUND_DB_PATH"] = str(db_path)
            os.environ.pop("SNIFFHOUND_RUNTIME_MODE", None)
            try:
                import sniffhound.settings as settings_module
                import sniffhound.app as app_module

                importlib.reload(settings_module)
                app_module = importlib.reload(app_module)

                self.assertEqual(app_module.runtime.mode, "sniffer")
                self.assertEqual(app_module.store.get_runtime_config("runtime_mode", ""), "sniffer")
                app_module.store.close()
            finally:
                if previous_db is None:
                    os.environ.pop("SNIFFHOUND_DB_PATH", None)
                else:
                    os.environ["SNIFFHOUND_DB_PATH"] = previous_db
                if previous_mode is None:
                    os.environ.pop("SNIFFHOUND_RUNTIME_MODE", None)
                else:
                    os.environ["SNIFFHOUND_RUNTIME_MODE"] = previous_mode

    def test_runtime_api_exposes_and_updates_sniffer_interfaces(self):
        _auth_module, app_module = _reload_auth_stack("0")

        with patch.object(app_module.sniffer, "list_available_interfaces", return_value=["eth0", "wlan0"]):
            app_module.runtime.set_sniffer_interfaces([])

            get_request = Request("GET", "/api/runtime/", "", {}, b"", ("127.0.0.1", 0))
            get_response = app_module.app.dispatch(get_request)
            get_payload = json.loads(get_response.body.decode("utf-8"))

            self.assertEqual(get_response.status, 200)
            self.assertEqual(get_payload["sniffer"]["available_interfaces"], ["eth0", "wlan0"])
            self.assertEqual(get_payload["sniffer"]["selected_interface"], "")
            self.assertEqual(get_payload["sniffer"]["selected_interfaces"], [])

            post_request = Request(
                "POST",
                "/api/runtime/",
                "",
                {"content-type": "application/json"},
                json.dumps({"interfaces": ["wlan0", "eth0", "wlan0"]}).encode("utf-8"),
                ("127.0.0.1", 0),
            )
            post_response = app_module.app.dispatch(post_request)
            post_payload = json.loads(post_response.body.decode("utf-8"))

            self.assertEqual(post_response.status, 200)
            self.assertEqual(post_payload["sniffer"]["selected_interface"], "")
            self.assertEqual(post_payload["sniffer"]["selected_interfaces"], ["wlan0", "eth0"])

    def test_runtime_api_supports_start_and_stop_actions(self):
        _auth_module, app_module = _reload_auth_stack("0")

        with patch.object(app_module.runtime, "set_mode", return_value={"mode": "honeypot"}) as set_mode_mock, patch.object(
            app_module.runtime, "start", return_value={"mode": "honeypot", "active": {"running": True}}
        ) as start_mock:
            start_request = Request(
                "POST",
                "/api/runtime/",
                "",
                {"content-type": "application/json"},
                json.dumps({"mode": "honeypot", "action": "start"}).encode("utf-8"),
                ("127.0.0.1", 0),
            )
            start_response = app_module.app.dispatch(start_request)
            start_payload = json.loads(start_response.body.decode("utf-8"))

            self.assertEqual(start_response.status, 200)
            self.assertEqual(start_payload["mode"], "honeypot")
            set_mode_mock.assert_called_once_with("honeypot")
            start_mock.assert_called_once()

        with patch.object(app_module.runtime, "stop", return_value={"mode": "sniffer", "active": {"running": False}}) as stop_mock:
            stop_request = Request(
                "POST",
                "/api/runtime/",
                "",
                {"content-type": "application/json"},
                json.dumps({"mode": "sniffer", "action": "stop"}).encode("utf-8"),
                ("127.0.0.1", 0),
            )
            stop_response = app_module.app.dispatch(stop_request)
            stop_payload = json.loads(stop_response.body.decode("utf-8"))

            self.assertEqual(stop_response.status, 200)
            self.assertFalse(stop_payload["active"]["running"])
            stop_mock.assert_called_once()

    def test_manage_candidate_ports_scan_requested_block(self):
        import sniffhound.manage as manage_module

        self.assertEqual(
            manage_module._candidate_ports(45678),
            (45678, 45670, 45671, 45672, 45673, 45674, 45675, 45676, 45677, 45679),
        )

    def test_manage_console_autocomplete_and_aliases(self):
        import sniffhound.manage as manage_module

        self.assertEqual(manage_module._resolve_console_command("/stats"), "/status")
        self.assertIn(
            "/stats",
            manage_module._build_console_completion_candidates("/st", "/st", 0),
        )
        self.assertEqual(
            manage_module._build_console_completion_candidates("/mode s", "s", len("/mode ")),
            ["sniffer"],
        )

    def test_manage_console_alias_executes_status_command(self):
        import sniffhound.manage as manage_module

        class DummyRuntime:
            def snapshot(self):
                return {
                    "mode": "sniffer",
                    "active": {
                        "running": True,
                        "packets_seen": 12,
                    },
                }

        class DummyHub:
            def list_clients(self):
                return [{"id": 1}, {"id": 2}]

        output = io.StringIO()
        with redirect_stdout(output):
            manage_module._handle_console_line(
                "/stats",
                host="127.0.0.1",
                port=45678,
                runtime=DummyRuntime(),
                hub=DummyHub(),
                append_chat_message=lambda *args, **kwargs: {},
            )

        self.assertIn("[status] mode=sniffer", output.getvalue())
        self.assertIn("ws_clients=2", output.getvalue())

    def test_manage_stop_interactive_console_closes_input_and_joins_thread(self):
        import sniffhound.manage as manage_module

        class DummyThread:
            def __init__(self):
                self.join_called = False

            def is_alive(self):
                return True

            def join(self, timeout=None):
                self.join_called = True
                self.timeout = timeout

        class DummyInput:
            def __init__(self):
                self.closed = False

            def close(self):
                self.closed = True

        thread = DummyThread()
        input_stream = DummyInput()

        manage_module._stop_interactive_console(thread, input_stream=input_stream, join_timeout=0.25)

        self.assertTrue(input_stream.closed)
        self.assertTrue(thread.join_called)
        self.assertEqual(thread.timeout, 0.25)

    def test_manage_stop_interactive_console_ignores_keyboard_interrupt_during_join(self):
        import sniffhound.manage as manage_module

        class DummyThread:
            def is_alive(self):
                return True

            def join(self, timeout=None):
                raise KeyboardInterrupt

        class DummyInput:
            closed = False

            def close(self):
                self.closed = True

        input_stream = DummyInput()
        manage_module._stop_interactive_console(DummyThread(), input_stream=input_stream, join_timeout=0.25)
        self.assertTrue(input_stream.closed)

    def test_manage_startup_banner_uses_hound_icon_and_link_line(self):
        import sniffhound.manage as manage_module
        import sniffhound.auth as auth_module

        output = io.StringIO()
        with patch.object(auth_module, "get_session_token", return_value="Ab12Cd34"), patch.object(
            auth_module, "REQUIRE_AUTH", True
        ), redirect_stdout(output):
            manage_module._print_startup_banner("127.0.0.1", 45678)

        banner = output.getvalue()
        self.assertIn("🐕 SNIFFHOUND v0.1.0", banner)
        self.assertIn("Link: http://127.0.0.1:45678/", banner)
        self.assertNotIn("Dashboard:", banner)
        self.assertNotIn("URL:", banner)

    def test_manage_selects_fallback_port_when_requested_port_is_occupied(self):
        import sniffhound.manage as manage_module

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind(("127.0.0.1", 0))
            host, port = sock.getsockname()
            selected = manage_module._select_listen_port(host, port)

        self.assertIsNotNone(selected)
        self.assertIn(selected, manage_module._candidate_ports(port))
        self.assertNotEqual(selected, port)

    def test_manage_main_uses_fallback_port(self):
        import sniffhound.app as app_module
        import sniffhound.manage as manage_module

        with patch.object(manage_module, "HOST", "127.0.0.1"), patch.object(
            manage_module, "PORT", 45678
        ), patch.object(
            manage_module, "_select_listen_port", return_value=45670
        ), patch.object(
            manage_module, "_ensure_admin_privileges", return_value=True
        ), patch.object(
            manage_module, "_print_port_fallback_notice"
        ) as notice_mock, patch.object(
            manage_module, "_print_startup_banner"
        ) as banner_mock, patch.object(
            app_module, "bootstrap_capture"
        ), patch.object(
            app_module, "shutdown_capture"
        ), patch.object(
            app_module.app, "run", side_effect=KeyboardInterrupt
        ) as run_mock:
            exit_code = manage_module.main()

        self.assertEqual(exit_code, 0)
        notice_mock.assert_called_once_with(45678, 45670)
        banner_mock.assert_called_once_with("127.0.0.1", 45670)
        run_mock.assert_called_once_with("127.0.0.1", 45670)

    def test_manage_exits_cleanly_when_no_fallback_port_is_available(self):
        import sniffhound.manage as manage_module

        with patch.object(manage_module, "HOST", "127.0.0.1"), patch.object(
            manage_module, "PORT", 45678
        ), patch.object(
            manage_module, "_select_listen_port", return_value=None
        ), patch.object(
            manage_module, "_ensure_admin_privileges", return_value=True
        ), patch.object(
            manage_module, "_print_address_in_use_error"
        ) as error_mock, patch.object(
            manage_module, "_print_startup_banner"
        ) as banner_mock:
            exit_code = manage_module.main()

        self.assertEqual(exit_code, 1)
        error_mock.assert_called_once_with("127.0.0.1", 45678)
        banner_mock.assert_not_called()

    def test_static_file_response_uses_body(self):
        import sniffhound.app as app_module

        with tempfile.TemporaryDirectory() as tmp_dir:
            file_path = Path(tmp_dir) / "asset.txt"
            file_path.write_text("static payload", encoding="utf-8")

            response = app_module._static_file_response(file_path)
            self.assertIsNotNone(response)
            self.assertEqual(response.status, 200)
            self.assertEqual(response.body, b"static payload")
            self.assertEqual(response.headers.get("Content-Type"), "text/plain")

    def test_frontend_dist_resolution_prefers_packaged_assets(self):
        import sniffhound.app as app_module

        with tempfile.TemporaryDirectory() as tmp_dir:
            base = Path(tmp_dir)
            packaged_dist = base / "site-packages" / "sniffhound" / "_frontend_dist"
            packaged_dist.mkdir(parents=True)
            (packaged_dist / "index.html").write_text("packaged build", encoding="utf-8")

            previous_source = app_module.SOURCE_FRONTEND_DIST_DIR
            previous_package = app_module.PACKAGE_FRONTEND_DIST_DIR
            previous_override = os.environ.pop("SNIFFHOUND_FRONTEND_DIST", None)
            try:
                app_module.SOURCE_FRONTEND_DIST_DIR = base / "missing" / "frontend" / "dist"
                app_module.PACKAGE_FRONTEND_DIST_DIR = packaged_dist

                resolved = app_module._resolve_frontend_dist_dir()
                self.assertEqual(resolved, packaged_dist)
            finally:
                app_module.SOURCE_FRONTEND_DIST_DIR = previous_source
                app_module.PACKAGE_FRONTEND_DIST_DIR = previous_package
                if previous_override is not None:
                    os.environ["SNIFFHOUND_FRONTEND_DIST"] = previous_override

    def test_ports_endpoint_exposes_rich_packet_context(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "traffic.db"
            previous_db = os.environ.get("SNIFFHOUND_DB_PATH")
            previous_auth = os.environ.get("SNIFFHOUND_REQUIRE_AUTH")
            os.environ["SNIFFHOUND_DB_PATH"] = str(db_path)
            os.environ["SNIFFHOUND_REQUIRE_AUTH"] = "0"
            try:
                _settings_module, _auth_module, app_module = _reload_runtime_stack("0")

                app_module.store.register_packet(
                    {
                        "session_id": 7,
                        "interface": "eth0",
                        "direction": "outbound",
                        "proto": "tcp",
                        "src_ip": "192.0.2.10",
                        "dst_ip": "198.51.100.20",
                        "src_port": 54321,
                        "dst_port": 443,
                        "summary": "TLS handshake",
                        "payload_text": "GET / HTTP/1.1",
                        "banner_text": "HTTP request",
                        "tags": [{"key": "service", "value": "https"}],
                        "rule_hits": [{"rule_id": "tls", "label": "TLS"}],
                    }
                )

                request = Request("GET", "/ports/", "proto=tcp&mode=sniffer", {}, b"", ("127.0.0.1", 0))
                response = app_module.app.dispatch(request)
                payload = json.loads(response.body.decode("utf-8"))

                self.assertEqual(response.status, 200)
                self.assertEqual(len(payload), 1)
                self.assertEqual(payload[0]["interface"], "eth0")
                self.assertEqual(payload[0]["src_ip"], "192.0.2.10")
                self.assertEqual(payload[0]["dst_ip"], "198.51.100.20")
                self.assertEqual(payload[0]["src_port"], 54321)
                self.assertEqual(payload[0]["dst_port"], 443)
                self.assertEqual(payload[0]["payload_text"], "GET / HTTP/1.1")
                self.assertEqual(payload[0]["banner_text"], "HTTP request")
                self.assertEqual(payload[0]["tags"][0]["value"], "https")
                self.assertEqual(payload[0]["rule_hits"][0]["label"], "TLS")
                app_module.store.close()
            finally:
                if previous_db is None:
                    os.environ.pop("SNIFFHOUND_DB_PATH", None)
                else:
                    os.environ["SNIFFHOUND_DB_PATH"] = previous_db
                if previous_auth is None:
                    os.environ.pop("SNIFFHOUND_REQUIRE_AUTH", None)
                else:
                    os.environ["SNIFFHOUND_REQUIRE_AUTH"] = previous_auth

    def test_soc_analysis_endpoint_returns_iterative_triage(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "traffic.db"
            previous_db = os.environ.get("SNIFFHOUND_DB_PATH")
            previous_auth = os.environ.get("SNIFFHOUND_REQUIRE_AUTH")
            os.environ["SNIFFHOUND_DB_PATH"] = str(db_path)
            os.environ["SNIFFHOUND_REQUIRE_AUTH"] = "0"
            try:
                _settings_module, _auth_module, app_module = _reload_runtime_stack("0")

                app_module.store.register_packet(
                    {
                        "session_id": 21,
                        "interface": "eth0",
                        "direction": "unknown",
                        "proto": "tcp",
                        "src_ip": "127.0.0.1",
                        "dst_ip": "127.0.0.1",
                        "src_port": 45670,
                        "dst_port": 45670,
                        "summary": "Loopback packet",
                        "payload_text": "{\"type\":\"telemetry\",\"packet\":1}",
                        "banner_text": "",
                        "tags": [{"key": "role", "value": "loopback"}],
                    }
                )
                app_module.store.register_packet(
                    {
                        "session_id": 22,
                        "interface": "eth0",
                        "direction": "outbound",
                        "proto": "udp",
                        "src_ip": "72.249.55.101",
                        "dst_ip": "192.168.88.250",
                        "src_port": 443,
                        "dst_port": 51820,
                        "summary": "Tunnel packet",
                        "payload_text": "GET / HTTP/1.1",
                        "banner_text": "HTTP request",
                        "tags": [{"key": "service", "value": "vpn"}],
                    }
                )

                request = Request("GET", "/api/soc/analysis/", "cycles=4&limit=500", {}, b"", ("127.0.0.1", 0))
                response = app_module.app.dispatch(request)
                payload = json.loads(response.body.decode("utf-8"))

                self.assertEqual(response.status, 200)
                self.assertIn("soc_summary", payload)
                self.assertEqual(len(payload["cycles"]), 4)
                self.assertGreaterEqual(payload["soc_summary"]["findings_total"], 1)
                self.assertGreaterEqual(len(payload["findings"]), 1)
                self.assertGreaterEqual(len(payload["questions"]), 1)
            finally:
                try:
                    app_module.store.close()
                except NameError:
                    pass
                if previous_db is None:
                    os.environ.pop("SNIFFHOUND_DB_PATH", None)
                else:
                    os.environ["SNIFFHOUND_DB_PATH"] = previous_db
                if previous_auth is None:
                    os.environ.pop("SNIFFHOUND_REQUIRE_AUTH", None)
                else:
                    os.environ["SNIFFHOUND_REQUIRE_AUTH"] = previous_auth

    def test_banners_endpoint_filters_honeypot_mode_and_keeps_packet_context(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "traffic.db"
            previous_db = os.environ.get("SNIFFHOUND_DB_PATH")
            previous_auth = os.environ.get("SNIFFHOUND_REQUIRE_AUTH")
            os.environ["SNIFFHOUND_DB_PATH"] = str(db_path)
            os.environ["SNIFFHOUND_REQUIRE_AUTH"] = "0"
            try:
                _settings_module, _auth_module, app_module = _reload_runtime_stack("0")

                app_module.store.register_packet(
                    {
                        "session_id": 11,
                        "interface": "eth0",
                        "direction": "outbound",
                        "proto": "tcp",
                        "src_ip": "192.0.2.15",
                        "dst_ip": "198.51.100.21",
                        "src_port": 50000,
                        "dst_port": 80,
                        "summary": "HTTP request",
                        "payload_text": "GET / HTTP/1.1",
                        "banner_text": "HTTP request",
                    }
                )
                app_module.store.register_packet(
                    {
                        "session_id": 12,
                        "interface": "honeypot:53",
                        "direction": "inbound",
                        "proto": "udp",
                        "src_ip": "203.0.113.50",
                        "dst_ip": "127.0.0.1",
                        "src_port": 53535,
                        "dst_port": 53,
                        "summary": "DNS message",
                        "payload_text": "query example.com",
                        "banner_text": "DNS message",
                        "tags": [{"key": "mode", "value": "honeypot"}],
                    }
                )

                request = Request("GET", "/banners/", "mode=honeypot", {}, b"", ("127.0.0.1", 0))
                response = app_module.app.dispatch(request)
                payload = json.loads(response.body.decode("utf-8"))

                self.assertEqual(response.status, 200)
                self.assertEqual(len(payload), 1)
                self.assertEqual(payload[0]["interface"], "honeypot:53")
                self.assertEqual(payload[0]["direction"], "inbound")
                self.assertEqual(payload[0]["src_ip"], "203.0.113.50")
                self.assertEqual(payload[0]["dst_ip"], "127.0.0.1")
                self.assertEqual(payload[0]["response_plain"], "DNS message")
                self.assertEqual(payload[0]["tags"][0]["value"], "honeypot")
                app_module.store.close()
            finally:
                if previous_db is None:
                    os.environ.pop("SNIFFHOUND_DB_PATH", None)
                else:
                    os.environ["SNIFFHOUND_DB_PATH"] = previous_db
                if previous_auth is None:
                    os.environ.pop("SNIFFHOUND_REQUIRE_AUTH", None)
                else:
                    os.environ["SNIFFHOUND_REQUIRE_AUTH"] = previous_auth
