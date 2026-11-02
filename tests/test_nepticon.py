"""Integration tests for the Nepticon TLS fleet protocol.

Run from the repository root::

    python -m unittest discover -s tests -v

The suite starts a real fleet server and a real agent on ``127.0.0.1`` with a
temporary CA and certificates, then exercises framing, the HMAC handshake,
remote command output containing braces, telemetry, fleet operations and
SHA-256 verified file transfers.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import shutil
import socket
import ssl
import struct
import sys
import threading
import time
import unittest
import uuid
from pathlib import Path
from typing import Any, Dict

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from client import Agent, coloring
from main import FleetServer
from nepticon.certs import generate_certificates
from nepticon.config import open_settings
from nepticon.protocol import (
    AUTH_FAIL,
    MAX_FRAME_SIZE,
    FrameTooLarge,
    build_hello,
    make_frame,
    recv_frame,
    send_frame,
    token_fingerprint,
)
from nepticon.audit import AuditLog
from nepticon.ui import format_duration


class NepticonIntegrationTests(unittest.TestCase):
    server: FleetServer
    agent: Agent
    node: Any
    base: Path

    @classmethod
    def setUpClass(cls) -> None:
        # Note: tempfile.mkdtemp() can create directories whose ACLs are not
        # writable inside the DSH Windows sandbox; a plain mkdir is reliable.
        cls.base = ROOT / f".nepticon-tests-{uuid.uuid4().hex[:8]}"
        cls.base.mkdir()
        certs = generate_certificates(
            cls.base / "certs",
            hostname="localhost",
            extra_sans=["127.0.0.1", "::1"],
        )
        cls.certs = certs
        cls.token = "integration-token-" + hashlib.sha256(b"nepticon").hexdigest()[:24]

        server_config = cls.base / "server-config.json"
        server_config.write_text(
            json.dumps(
                {
                    "host": "127.0.0.1",
                    "token": cls.token,
                    "cert": str(certs["cert"]),
                    "key": str(certs["key"]),
                    "ca": str(certs["ca"]),
                    "audit_log": str(cls.base / "logs" / "audit.jsonl"),
                    "downloads": str(cls.base / "server-downloads"),
                    "heartbeat_interval": 30.0,
                    "request_timeout": 10.0,
                    "transfer_timeout": 20.0,
                    "color": False,
                    "animations": False,
                }
            ),
            encoding="utf-8",
        )
        server_settings = open_settings(
            "server", config_path=server_config, cli={"color": False, "animations": False}
        )
        # Use an ephemeral port to make the suite safe on shared CI hosts.
        server_settings = dataclasses.replace(server_settings, port=0)
        cls.server = FleetServer(server_settings)
        cls.server.start()

        agent_config = cls.base / "agent-config.json"
        agent_config.write_text(
            json.dumps(
                {
                    "host": "127.0.0.1",
                    "port": cls.server.port,
                    "token": cls.token,
                    "ca": str(certs["ca"]),
                    "node_name": "test-node",
                    "downloads": str(cls.base / "agent-downloads"),
                    "color": False,
                    "animations": False,
                }
            ),
            encoding="utf-8",
        )
        agent_settings = open_settings(
            "agent", config_path=agent_config, cli={"color": False, "animations": False}
        )
        cls.agent = Agent(agent_settings)
        cls.agent.start_background()

        deadline = time.time() + 20
        while time.time() < deadline:
            nodes = cls.server.nodes_snapshot()
            if nodes:
                cls.node = nodes[0]
                return
            if cls.agent._launcher and not cls.agent._launcher.is_alive():
                break
            time.sleep(0.05)
        audit_tail = cls.server.audit.tail(10)
        cls.agent.stop()
        cls.server.stop()
        raise RuntimeError(
            "agent did not register within 20s; launch_thread_alive=%r audit=%s"
            % (
                bool(cls.agent._launcher and cls.agent._launcher.is_alive()),
                audit_tail,
            )
        )

    @classmethod
    def tearDownClass(cls) -> None:
        if hasattr(cls, "agent"):
            cls.agent.stop()
            thread = getattr(cls.agent, "_launcher", None)
            if thread is not None:
                thread.join(timeout=3)
        if hasattr(cls, "server"):
            cls.server.stop()
        if hasattr(cls, "base"):
            shutil.rmtree(cls.base, ignore_errors=True)

    # -- framing and TLS ----------------------------------------------------

    def test_framing_large_payload_with_braces(self) -> None:
        left, right = socket.socketpair()
        payload = {
            "v": 1,
            "type": "TEST",
            "id": "frame-1",
            "data": {
                "blob": "x" * (300 * 1024),
                "json": {"a": {"b": [1, 2, 3]}, "text": "{not-a-format-string}"},
            },
        }
        sender = threading.Thread(target=send_frame, args=(left, payload))
        sender.start()
        try:
            received = recv_frame(right)
        finally:
            sender.join(timeout=5)
            left.close()
            right.close()
        self.assertEqual(received["data"]["blob"], payload["data"]["blob"])
        self.assertEqual(received["data"]["json"], payload["data"]["json"])
        self.assertEqual(len(received["data"]["blob"]), 300 * 1024)

    def test_framing_rejects_oversized_header(self) -> None:
        left, right = socket.socketpair()
        try:
            left.sendall(struct.pack(">I", MAX_FRAME_SIZE + 1))
            with self.assertRaises(FrameTooLarge):
                recv_frame(right)
        finally:
            left.close()
            right.close()

    def test_tls_framing_roundtrip(self) -> None:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(str(self.certs["cert"]), str(self.certs["key"]))
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(5)
        port = listener.getsockname()[1]
        received: Dict[str, Any] = {}
        errors: list[BaseException] = []

        def serve() -> None:
            try:
                raw, _ = listener.accept()
                with context.wrap_socket(raw, server_side=True) as tls:
                    frame = recv_frame(tls)
                    received["frame"] = frame
                    send_frame(
                        tls,
                        make_frame(
                            "ECHO",
                            {
                                "length": len(frame["data"]["blob"]),
                                "json": frame["data"]["json"],
                            },
                            frame_id=frame.get("id"),
                        ),
                    )
            except BaseException as exc:  # noqa: BLE001 - surfaced in the test
                errors.append(exc)
            finally:
                listener.close()

        thread = threading.Thread(target=serve)
        thread.start()
        client_context = ssl.create_default_context(
            ssl.Purpose.SERVER_AUTH, cafile=str(self.certs["ca"])
        )
        payload = {
            "v": 1,
            "type": "TEST",
            "id": "tls-frame",
            "data": {"blob": "{" * (600 * 1024), "json": {"nested": {"ok": True}}},
        }
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
                with client_context.wrap_socket(raw, server_hostname="127.0.0.1") as tls:
                    tls.settimeout(10)
                    send_frame(tls, payload)
                    response = recv_frame(tls)
        finally:
            thread.join(timeout=10)
        self.assertEqual(errors, [])
        self.assertEqual(response["data"]["length"], 600 * 1024)
        self.assertEqual(response["data"]["json"], {"nested": {"ok": True}})

    # -- handshake ----------------------------------------------------------

    def test_authenticated_handshake_fields(self) -> None:
        self.assertIsNotNone(getattr(self, "node", None))
        hello = self.node.hello
        self.assertEqual(hello["hostname"], "test-node")
        self.assertGreaterEqual(int(hello["cpu_cores"]), 1)
        self.assertIn(hello["privilege_level"], ("admin", "user"))
        self.assertIn("os_info", hello)
        self.assertIn("arch", hello)
        self.assertIn("cwd", hello)
        self.assertEqual(hello["agent_version"], "2.0.0")
        self.assertEqual(hello["auth"]["algorithm"], "HMAC-SHA256")
        self.assertEqual(hello["auth"]["token_id"], token_fingerprint(self.token))
        serialized = json.dumps(hello)
        self.assertNotIn(self.token, serialized, "the raw token must never be sent")
        self.assertEqual(self.agent.node_id, self.node.node_id)
        self.assertEqual(self.agent.server_version, "2.0.0")

    def test_wrong_token_is_rejected(self) -> None:
        client_context = ssl.create_default_context(
            ssl.Purpose.SERVER_AUTH, cafile=str(self.certs["ca"])
        )
        hello = build_hello(
            token="definitely-the-wrong-token",
            hostname="intruder",
            os_info="test",
            arch="test",
            cpu_cores=2,
            agent_version="2.0.0",
            privilege_level="user",
            cwd="/tmp",
            username="nobody",
            uptime_seconds=1.0,
        )
        before = self.server.node_count
        with socket.create_connection(("127.0.0.1", self.server.port), timeout=5) as raw:
            with client_context.wrap_socket(raw, server_hostname="127.0.0.1") as tls:
                tls.settimeout(5)
                send_frame(tls, hello)
                reply = recv_frame(tls)
        self.assertEqual(reply["type"], AUTH_FAIL)
        self.assertTrue(str(reply["data"].get("reason", "")))
        self.assertIn("token", str(reply["data"]["reason"]).lower())
        self.assertEqual(self.server.node_count, before)

    # -- command execution and braces --------------------------------------

    def test_command_output_with_braces_is_not_formatted(self) -> None:
        script = self.base / "brace_output.py"
        script.write_text(
            "import json, sys\n"
            "print(json.dumps({'outer': {'inner': [1, 2, 3]}, 'text': 'a{b}c%d{0}'}))\n"
            "print('literal {braces} and %s survive', file=sys.stderr)\n"
            "sys.exit(3)\n",
            encoding="utf-8",
        )
        result = self.node.execute(f'"{sys.executable}" "{script}"')
        self.assertEqual(result["exit_code"], 3)
        self.assertIn("{braces}", result["stderr"])
        self.assertIn("%s survive", result["stderr"])
        payload = json.loads(result["stdout"].strip())
        self.assertEqual(payload["outer"]["inner"], [1, 2, 3])
        self.assertEqual(payload["text"], "a{b}c%d{0}")

        echo = self.node.execute('echo {"alpha": {"beta": 1}}')
        self.assertEqual(echo["exit_code"], 0)
        self.assertIn('{"alpha": {"beta": 1}}', echo["stdout"])

    def test_broadcast_and_fleet_health(self) -> None:
        results = self.server.broadcast('echo "fleet-{ok}"')
        self.assertEqual(len(results), 1)
        self.assertTrue(results[0]["ok"], results[0]["error"])
        self.assertIn("fleet-{ok}", results[0]["result"]["stdout"])

        health = self.server.fleet_health(timeout=15)
        self.assertEqual(len(health), 1)
        self.assertTrue(health[0]["ok"], health[0]["error"])
        self.assertGreater(health[0]["health"]["memory"]["total_mb"], 0)

    # -- telemetry ----------------------------------------------------------

    def test_health_telemetry(self) -> None:
        health = self.node.audited("health")
        self.assertIsInstance(health, dict)
        cpu = health["cpu"]
        self.assertGreaterEqual(cpu["cores"], 1)
        self.assertGreaterEqual(cpu["percent"], 0.0)
        self.assertLessEqual(cpu["percent"], 100.0)
        memory = health["memory"]
        self.assertGreater(memory["total_mb"], 0)
        self.assertGreaterEqual(memory["used_mb"], 0)
        self.assertGreaterEqual(memory["percent"], 0.0)
        disk = health["disk"]
        self.assertGreater(disk["total_gb"], 0)
        self.assertGreaterEqual(disk["percent"], 0.0)
        self.assertGreaterEqual(health["uptime_seconds"], 0)
        self.assertRegex(health["python_version"], r"^\d+\.\d+")
        self.assertIsInstance(health["network"], list)
        self.assertIsInstance(health["errors"], list)
        self.assertIn("os_info", health)
        self.assertIn("arch", health)

    def test_sysinfo_ps_and_env(self) -> None:
        info = self.node.audited("sysinfo")
        self.assertEqual(info["hostname"], socket.gethostname())
        self.assertIn("python_executable", info)
        self.assertIn("boot_time", info)
        ps = self.node.audited("ps", {"limit": 3})
        self.assertLessEqual(len(ps["processes"]), 3)
        for process in ps["processes"]:
            self.assertIn("pid", process)
            self.assertIn("rss_mb", process)
        os.environ["NEPTICON_TEST_API_TOKEN"] = "super-secret-value"
        try:
            env = self.node.audited("env")
        finally:
            os.environ.pop("NEPTICON_TEST_API_TOKEN", None)
        variables = {entry["name"]: entry["value"] for entry in env["variables"]}
        self.assertIn("NEPTICON_TEST_API_TOKEN", variables)
        self.assertEqual(variables["NEPTICON_TEST_API_TOKEN"], "***redacted***")
        self.assertGreater(env["count"], 0)
        self.assertTrue(any(item["name"] == "nepticon-env" for item in env["services"]))

    # -- file transfer ------------------------------------------------------

    def test_sha256_verified_file_transfer(self) -> None:
        content = os.urandom(200_000)
        source = self.base / "upload-source.bin"
        source.write_bytes(content)
        expected_sha = hashlib.sha256(content).hexdigest()
        remote = self.base / "agent-downloads" / "received-payload.bin"

        upload = self.node.upload_file(source, str(remote))
        self.assertEqual(upload["bytes"], len(content))
        self.assertEqual(upload["sha256"], expected_sha)
        self.assertEqual(remote.read_bytes(), content)

        download_source = self.base / "download-source.bin"
        download_source.write_bytes(content)
        download = self.node.download_file(
            str(download_source), dest_dir=self.base / "server-downloads"
        )
        self.assertEqual(download["bytes"], len(content))
        self.assertEqual(download["sha256"], expected_sha)
        self.assertEqual(Path(download["path"]).read_bytes(), content)

        records = self.server.audit.tail(200)
        transfers = [
            record
            for record in records
            if record.get("event") == "file_transfer"
            and (record.get("detail") or {}).get("direction") in ("upload", "download")
        ]
        self.assertGreaterEqual(len(transfers), 2)
        matching = [
            record for record in transfers if record["detail"].get("sha256") == expected_sha
        ]
        self.assertEqual(
            {"upload", "download"},
            {record["detail"]["direction"] for record in matching},
        )
        for record in matching:
            self.assertTrue(record["detail"]["ok"])

    # -- audit --------------------------------------------------------------

    def test_audit_chain_and_content(self) -> None:
        # Make this test independent of alphabetical execution order.
        self.node.execute("echo audit-probe")
        probe = self.base / "audit-probe.bin"
        probe.write_bytes(b"audit-transfer-probe")
        self.node.upload_file(
            probe, str(self.base / "agent-downloads" / "audit-probe.bin")
        )
        verification = self.server.audit.verify()
        self.assertTrue(verification["ok"], verification)
        self.assertGreater(verification["records"], 0)
        records = self.server.audit.tail(300)
        events = {record["event"] for record in records}
        self.assertIn("server_start", events)
        self.assertIn("node_connect", events)
        self.assertIn("command", events)
        self.assertIn("file_transfer", events)
        for record in records:
            self.assertEqual(len(record["hash"]), 64)
            self.assertEqual(len(record["prev"]), 64)

        # Tampering with any historical record must break the local chain.
        original = self.server.audit.path.read_text(encoding="utf-8").splitlines()
        tampered = self.base / "tampered-audit.jsonl"
        first = json.loads(original[0])
        first["detail"]["tampered"] = True
        modified = [json.dumps(first, ensure_ascii=False)] + original[1:]
        tampered.write_text("\n".join(modified) + "\n", encoding="utf-8")
        result = AuditLog(tampered).verify()
        self.assertFalse(result["ok"])
        self.assertEqual(result["line"], 1)

    def test_duration_formatting(self) -> None:
        self.assertEqual(format_duration(0), "0s")
        self.assertEqual(format_duration(65), "1m 05s")
        self.assertEqual(format_duration(None), "—")

    def test_coloring_returns_text_not_ssl_context(self) -> None:
        rendered = coloring("[+]", "coloring-regression")
        self.assertIsInstance(rendered, str)
        self.assertIn("coloring-regression", rendered)


class ReconnectTests(unittest.TestCase):
    """Prove that a fresh socket is used after the server comes back."""

    def setUp(self) -> None:
        self.base = ROOT / f".nepticon-reconnect-{uuid.uuid4().hex[:8]}"
        self.base.mkdir()
        self.certs = generate_certificates(
            self.base / "certs", hostname="localhost", extra_sans=["127.0.0.1"]
        )
        self.token = "reconnect-token-" + uuid.uuid4().hex
        probe = socket.socket()
        probe.bind(("127.0.0.1", 0))
        self.port = probe.getsockname()[1]
        probe.close()
        self.server_settings = open_settings(
            "server",
            config_path=self._write_config(
                "server",
                {
                    "host": "127.0.0.1",
                    "port": self.port,
                    "token": self.token,
                    "cert": str(self.certs["cert"]),
                    "key": str(self.certs["key"]),
                    "ca": str(self.certs["ca"]),
                    "audit_log": str(self.base / "audit.jsonl"),
                    "downloads": str(self.base / "downloads"),
                    "heartbeat_interval": 30.0,
                    "request_timeout": 5.0,
                    "transfer_timeout": 10.0,
                },
            ),
        )
        self.agent_settings = open_settings(
            "agent",
            config_path=self._write_config(
                "agent",
                {
                    "host": "127.0.0.1",
                    "port": self.port,
                    "token": self.token,
                    "ca": str(self.certs["ca"]),
                    "node_name": "reconnect-node",
                    "downloads": str(self.base / "agent-downloads"),
                },
            ),
        )
        self.server = FleetServer(self.server_settings)
        self.server.start()
        self.agent = Agent(self.agent_settings)
        self.agent.start_background()
        self._wait_for(lambda: self.server.node_count == 1, 15)

    def _write_config(self, role: str, values: Dict[str, Any]) -> Path:
        path = self.base / f"{role}.json"
        path.write_text(json.dumps(values), encoding="utf-8")
        return path

    def _wait_for(self, predicate: Any, timeout: float) -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if predicate():
                return
            time.sleep(0.05)
        self.fail("condition was not met before the deadline")

    def tearDown(self) -> None:
        self.agent.stop()
        self.server.stop()
        shutil.rmtree(self.base, ignore_errors=True)

    def test_agent_reconnects_after_server_restart(self) -> None:
        old_node = self.server.nodes_snapshot()[0]
        old_session = self.agent.session_id
        self.server.stop()
        self._wait_for(lambda: not self.agent.connected.is_set(), 10)

        restarted = FleetServer(self.server_settings)
        restarted.start()
        try:
            self._wait_for(lambda: restarted.node_count == 1, 20)
            self._wait_for(lambda: self.agent.connected.is_set(), 20)
            new_node = restarted.nodes_snapshot()[0]
            self.assertEqual(self.agent.node_id, new_node.node_id)
            self.assertEqual(new_node.hostname, "reconnect-node")
            self.assertGreater(new_node.connected_at, old_node.connected_at)
            self.assertNotEqual(self.agent.session_id, old_session)
        finally:
            self.server = restarted


if __name__ == "__main__":
    unittest.main(verbosity=2)
