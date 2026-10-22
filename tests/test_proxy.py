"""Tests for ProxyServer and end-to-end proxy processing flows."""

import unittest

from core.contracts import POLICY_VERSION
from proxy.config import ProxyConfig
from proxy.models import HOLD, ToolRequest
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

        # Check analysis event
        events = self.log.get_events_for_request("req-email-01")
        ai_events = [e for e in events if e["event_type"] == "AI_ANALYSIS"]
        self.assertEqual(len(ai_events), 1)
        payload = ai_events[0]["payload"]
        self.assertTrue(payload["analyser_failed"])
        self.assertEqual(payload["error_type"], "RuntimeError")
        self.assertIsNone(payload["signals"])

        # Failure on high-impact tool leads to HOLD
        self.assertEqual(resp.get("decision"), HOLD)

    def test_analyser_invalid_schema_leads_to_fallback_and_hold(self) -> None:
        analyser = FakeAnalyser(default_result={"malformed": "output"})
        server = ProxyServer(self.log, analyser, self.executor)
        resp = server.handle_tool_call(self.email_request)

        events = self.log.get_events_for_request("req-email-01")
        ai_events = [e for e in events if e["event_type"] == "AI_ANALYSIS"]
        self.assertEqual(len(ai_events), 1)
        self.assertTrue(ai_events[0]["payload"]["analyser_failed"])
        self.assertEqual(ai_events[0]["payload"]["error_type"], "ValueError")
        self.assertEqual(resp.get("decision"), HOLD)

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


if __name__ == "__main__":
    unittest.main()
