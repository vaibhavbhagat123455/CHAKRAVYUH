"""Tests for PolicyDecisionEngine and CHECKPOINT_DECISION event logging."""

import unittest

from core.contracts import POLICY_VERSION
from proxy.checkpoint import PolicyDecisionEngine
from proxy.models import ALLOW, DENY, HOLD, DecisionSignals, ToolRequest
from tests.fakes import FakeLog


class TestPolicyDecisionEngine(unittest.TestCase):
    """Test PolicyDecisionEngine evaluation and audit event emission."""

    def setUp(self) -> None:
        self.log = FakeLog()
        self.engine = PolicyDecisionEngine(policy_version=POLICY_VERSION, log=self.log)
        self.request = ToolRequest(
            request_id="req-eng-01",
            tool="summarize_document",
            arguments={"file": "synthetic_report.pdf"},
            purpose="Summarize document",
            scenario_id="scen-eng-01",
        )
        self.signals = DecisionSignals(
            prompt_injection=False,
            goal_drift=False,
            sensitive_data_risk="low",
            risk_score=0.1,
            recommended_action="ALLOW",
            reason="Low risk benign",
        )

    def test_evaluate_calls_decide_and_logs_checkpoint_decision(self) -> None:
        decision = self.engine.evaluate(self.request, self.signals)
        self.assertEqual(decision.decision, ALLOW)
        self.assertEqual(decision.request_id, "req-eng-01")

        # Verify event logged to FakeLog
        events = self.log.get_events_for_request("req-eng-01")
        self.assertEqual(len(events), 1)
        evt = events[0]
        self.assertEqual(evt["event_type"], "CHECKPOINT_DECISION")
        self.assertEqual(evt["request_id"], "req-eng-01")

        # Verify payload structure
        payload = evt["payload"]
        self.assertEqual(payload["decision"], ALLOW)
        self.assertEqual(payload["evidence_id"], decision.evidence_id)
        self.assertEqual(payload["rule_id"], decision.rule_id)
        self.assertEqual(payload["reason"], decision.reason)
        self.assertEqual(payload["policy_version"], POLICY_VERSION)
        self.assertEqual(payload["signals"], self.signals.to_dict())
        self.assertEqual(payload["subtype"], "CHECKPOINT_DECISION")

    def test_evaluate_with_signals_none(self) -> None:
        req = ToolRequest(
            request_id="req-eng-02",
            tool="send_email",
            arguments={"recipient": "dean@example.edu"},
            purpose="Send mail",
            scenario_id="scen-eng-02",
        )
        decision = self.engine.evaluate(req, None)
        self.assertEqual(decision.decision, HOLD)

        events = self.log.get_events_for_request("req-eng-02")
        self.assertEqual(len(events), 1)
        payload = events[0]["payload"]
        self.assertEqual(payload["decision"], HOLD)
        self.assertIsNone(payload["signals"])

    def test_evaluate_deny_logged(self) -> None:
        req = ToolRequest(
            request_id="req-eng-03",
            tool="export_records",
            arguments={"q": "all"},
            purpose="Export",
            scenario_id="scen-eng-03",
        )
        decision = self.engine.evaluate(req, self.signals)
        self.assertEqual(decision.decision, DENY)

        events = self.log.get_events_for_request("req-eng-03")
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["payload"]["decision"], DENY)


if __name__ == "__main__":
    unittest.main()
