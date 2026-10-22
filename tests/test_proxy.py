"""Tests for ProxyServer and end-to-end proxy processing flows."""

import unittest

from core.contracts import POLICY_VERSION
from proxy.config import ProxyConfig
from proxy.models import ALLOW, HOLD, ToolRequest
from proxy.server import ProxyServer
from tests.fakes import (
    FakeAnalyser,
    FakeApprovalService,
    FakeClock,
    FakeLog,
    SpyExecutor,
)


class TestProxyServerBasic(unittest.TestCase):
    """Test ProxyServer dependency injection and initial request logging."""

    def setUp(self) -> None:
        self.log = FakeLog()
        self.analyser = FakeAnalyser()
        self.executor = SpyExecutor()
        self.approval = FakeApprovalService()
        self.config = ProxyConfig()
        self.clock = FakeClock()
        self.server = ProxyServer(
            log=self.log,
            analyser=self.analyser,
            executor=self.executor,
            approval=self.approval,
            config=self.config,
            clock=self.clock,
        )
        self.request = ToolRequest(
            request_id="req-srv-01",
            tool="summarize_document",
            arguments={"file": "synthetic_report.pdf"},
            purpose="Summarize document",
            scenario_id="scen-srv-01",
        )

    def test_handle_tool_call_emits_request_received_first(self) -> None:
        response = self.server.handle_tool_call(self.request)
        self.assertIsNotNone(response)

        events = self.log.get_events_for_request("req-srv-01")
        self.assertGreaterEqual(len(events), 1)
        first_evt = events[0]
        self.assertEqual(first_evt["event_type"], "REQUEST_RECEIVED")
        self.assertEqual(first_evt["payload"]["request_id"], "req-srv-01")
        self.assertEqual(first_evt["payload"]["tool"], "summarize_document")
        self.assertEqual(first_evt["payload"]["arguments"], {"file": "synthetic_report.pdf"})
        self.assertEqual(first_evt["payload"]["purpose"], "Summarize document")
        self.assertEqual(first_evt["payload"]["scenario_id"], "scen-srv-01")


class TestProxyServerAnalyserFallback(unittest.TestCase):
    """Test safe fallback when AI analyser fails or produces invalid output."""

    def setUp(self) -> None:
        self.log = FakeLog()
        self.executor = SpyExecutor()
        self.email_request = ToolRequest(
            request_id="req-email-01",
            tool="send_email",
            arguments={"recipient": "dean@example.edu", "body": "Hello"},
            purpose="Send notification email",
            scenario_id="scen-email-01",
        )

    def test_analyser_called_with_tool_call_and_purpose(self) -> None:
        analyser = FakeAnalyser()
        server = ProxyServer(self.log, analyser, self.executor)
        server.handle_tool_call(self.email_request)

        self.assertEqual(len(analyser.calls), 1)
        self.assertEqual(analyser.calls[0]["original_goal"], self.email_request.purpose)
        self.assertEqual(analyser.calls[0]["tool_call"], self.email_request.to_dict())

    def test_analyser_exception_leads_to_hold_for_send_email(self) -> None:
        analyser = FakeAnalyser(exception_to_raise=RuntimeError("AI network timeout"))
        server = ProxyServer(self.log, analyser, self.executor)
        resp = server.handle_tool_call(self.email_request)

        events = self.log.get_events_for_request("req-email-01")
        ai_events = [e for e in events if e["event_type"] == "AI_ANALYSIS"]
        self.assertEqual(len(ai_events), 1)
        payload = ai_events[0]["payload"]
        self.assertTrue(payload["analyser_failed"])
        self.assertEqual(payload["error_type"], "RuntimeError")
        self.assertIsNone(payload["signals"])

        # Check response contains HOLD
        self.assertIn("HOLD", str(resp))

    def test_analyser_invalid_schema_leads_to_fallback_and_hold(self) -> None:
        analyser = FakeAnalyser(default_result={"malformed": "output"})
        server = ProxyServer(self.log, analyser, self.executor)
        resp = server.handle_tool_call(self.email_request)

        events = self.log.get_events_for_request("req-email-01")
        ai_events = [e for e in events if e["event_type"] == "AI_ANALYSIS"]
        self.assertEqual(len(ai_events), 1)
        self.assertTrue(ai_events[0]["payload"]["analyser_failed"])
        self.assertEqual(ai_events[0]["payload"]["error_type"], "ValueError")
        self.assertIn("HOLD", str(resp))

    def test_analyser_includes_model_version_when_returned(self) -> None:
        result = {
            "prompt_injection": False,
            "goal_drift": False,
            "sensitive_data_risk": "low",
            "risk_score": 0.05,
            "recommended_action": "ALLOW",
            "reason": "OK",
            "model_version": "gemini-threat-v1",
        }
        analyser = FakeAnalyser(default_result=result)
        server = ProxyServer(self.log, analyser, self.executor)
        server.handle_tool_call(self.email_request)

        events = self.log.get_events_for_request("req-email-01")
        ai_events = [e for e in events if e["event_type"] == "AI_ANALYSIS"]
        self.assertEqual(ai_events[0]["payload"]["model_version"], "gemini-threat-v1")


class TestProxyServerExecutionAndTrail(unittest.TestCase):
    """Test execution of ALLOW decisions and complete audit event trail."""

    def setUp(self) -> None:
        self.log = FakeLog()
        self.analyser = FakeAnalyser(default_result={
            "prompt_injection": False,
            "goal_drift": False,
            "sensitive_data_risk": "low",
            "risk_score": 0.05,
            "recommended_action": "ALLOW",
            "reason": "Safe summary verified",
        })
        self.executor = SpyExecutor(default_result={"status": "success", "simulated": True})
        self.server = ProxyServer(self.log, self.analyser, self.executor)
        self.allow_req = ToolRequest(
            request_id="req-allow-01",
            tool="summarize_document",
            arguments={"file": "synthetic_report.pdf"},
            purpose="Summarize document",
            scenario_id="scen-allow-01",
        )

    def test_allow_decision_execution_and_exact_event_order(self) -> None:
        resp = self.server.handle_tool_call(self.allow_req, rpc_id="rpc-100")

        # Executor must be called exactly once
        self.assertEqual(self.executor.call_count, 1)
        self.assertEqual(self.executor.calls[0]["tool"], "summarize_document")
        self.assertEqual(self.executor.calls[0]["arguments"], {"file": "synthetic_report.pdf"})

        # Response must be JSON-RPC success structure with decision, evidence_id, and tool result
        self.assertEqual(resp["jsonrpc"], "2.0")
        self.assertEqual(resp["id"], "rpc-100")
        result = resp["result"]
        self.assertEqual(result["decision"], ALLOW)
        self.assertTrue(result["evidence_id"].startswith("ev-"))
        self.assertTrue(result.get("tool_result") is not None or result.get("result") is not None)

        # Audit event sequence must match exact order
        events = self.log.get_events_for_request("req-allow-01")
        event_types = [e["event_type"] for e in events]
        expected_types = (
            ["REQUEST_RECEIVED", "AI_ANALYSIS"]
            + ["LAYER_EVALUATED"] * 7
            + ["CHECKPOINT_DECISION", "TOOL_STARTED", "TOOL_COMPLETED"]
        )
        self.assertEqual(event_types, expected_types)

        # Check layers order in LAYER_EVALUATED payloads
        layer_events = [e for e in events if e["event_type"] == "LAYER_EVALUATED"]
        self.assertEqual(len(layer_events), 7)
        layer_ids = [e["payload"]["layer_id"] for e in layer_events]
        self.assertEqual(layer_ids, ["DWAAR", "PEHCHAAN", "SMRITI", "SANKALP", "ASTRA", "MARYADA", "DRISHTI"])


if __name__ == "__main__":
    unittest.main()
