"""Tests for tool timeout and failure containment in ProxyServer."""

import contextlib
import io
import unittest

from proxy.executor import ToolTimeout
from proxy.jsonrpc import TOOL_FAILED
from proxy.models import ToolRequest
from proxy.server import ProxyServer
from tests.fakes import FakeAnalyser, FakeLog, SpyExecutor


class TestProxyServerContainment(unittest.TestCase):
    """Test containment of tool timeouts and execution failures without stdout tracebacks."""

    def setUp(self) -> None:
        self.log = FakeLog()
        self.analyser = FakeAnalyser(default_result={
            "prompt_injection": False,
            "goal_drift": False,
            "sensitive_data_risk": "low",
            "risk_score": 0.05,
            "recommended_action": "ALLOW",
            "reason": "Safe summary allow",
        })
        self.executor = SpyExecutor()
        self.server = ProxyServer(self.log, self.analyser, self.executor)
        self.request = ToolRequest(
            request_id="req-cont-01",
            tool="summarize_document",
            arguments={"file": "synthetic_report.pdf"},
            purpose="Summarize document",
            scenario_id="scen-cont-01",
        )

    def test_tool_timeout_emits_containment_and_returns_tool_failed(self) -> None:
        self.executor.exception_to_raise = ToolTimeout("Tool execution timed out after 0.1s")

        resp = self.server.handle_tool_call(self.request, rpc_id="rpc-to-1")

        self.assertEqual(resp["jsonrpc"], "2.0")
        self.assertEqual(resp["id"], "rpc-to-1")
        self.assertIn("error", resp)
        self.assertEqual(resp["error"]["code"], TOOL_FAILED)
        self.assertTrue(resp["error"]["data"]["evidence_id"].startswith("ev-"))

        events = self.log.get_events_for_request("req-cont-01")
        event_types = [e["event_type"] for e in events]
        self.assertIn("CONTAINMENT", event_types)
        self.assertNotIn("TOOL_COMPLETED", event_types)

        containment_evt = next(e for e in events if e["event_type"] == "CONTAINMENT")
        self.assertEqual(containment_evt["payload"]["subtype"], "TOOL_TIMEOUT")
        self.assertTrue(containment_evt["payload"]["evidence_id"].startswith("ev-"))

    def test_other_executor_exceptions_contained_same_way(self) -> None:
        self.executor.exception_to_raise = RuntimeError("Simulated unexpected tool crash")

        resp = self.server.handle_tool_call(self.request, rpc_id="rpc-crash-1")

        self.assertEqual(resp["error"]["code"], TOOL_FAILED)
        self.assertTrue(resp["error"]["data"]["evidence_id"].startswith("ev-"))

        events = self.log.get_events_for_request("req-cont-01")
        self.assertTrue(any(e["event_type"] == "CONTAINMENT" for e in events))

    def test_no_traceback_on_stdout(self) -> None:
        self.executor.exception_to_raise = RuntimeError("Hidden crash details")

        stdout_buf = io.StringIO()
        with contextlib.redirect_stdout(stdout_buf):
            self.server.handle_tool_call(self.request, rpc_id="rpc-quiet-1")

        self.assertEqual(stdout_buf.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
