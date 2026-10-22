"""Tests for proxy deterministic checkpoint evidence ID generation and decide skeleton."""

import unittest

from core.contracts import POLICY_VERSION
from proxy.checkpoint import (
    REASON_R1_UNALLOWED_TOOL,
    REASON_R2_EXTERNAL_SENSITIVE,
    REASON_R7_DEFAULT_HOLD,
    RULE_R1,
    RULE_R2,
    RULE_R3,
    RULE_R4,
    RULE_R5,
    RULE_R6,
    RULE_R7,
    decide,
    make_evidence_id,
)
from proxy.models import DENY, HOLD, Decision, DecisionSignals, ToolRequest
from proxy.policy import POLICY_V1


class TestEvidenceIdGeneration(unittest.TestCase):
    """Test deterministic evidence ID creation for requests and signals."""

    def setUp(self) -> None:
        self.request = ToolRequest(
            request_id="req-101",
            tool="summarize_document",
            arguments={"file": "synthetic_report.pdf"},
            purpose="Summarize report",
            scenario_id="scen-01",
        )
        self.signals = DecisionSignals(
            prompt_injection=False,
            goal_drift=False,
            sensitive_data_risk="low",
            risk_score=0.1,
            recommended_action="ALLOW",
            reason="Benign summary",
        )
        self.policy_version = "v1"

    def test_same_input_same_id(self) -> None:
        ev1 = make_evidence_id(self.request, self.signals, self.policy_version)
        ev2 = make_evidence_id(self.request, self.signals, self.policy_version)
        self.assertEqual(ev1, ev2)
        self.assertTrue(ev1.startswith("ev-"))
        self.assertEqual(len(ev1), 3 + 12)

    def test_signals_none_is_stable(self) -> None:
        ev1 = make_evidence_id(self.request, None, self.policy_version)
        ev2 = make_evidence_id(self.request, None, self.policy_version)
        self.assertEqual(ev1, ev2)
        self.assertTrue(ev1.startswith("ev-"))
        ev_with_signals = make_evidence_id(self.request, self.signals, self.policy_version)
        self.assertNotEqual(ev1, ev_with_signals)

    def test_changing_argument_changes_id(self) -> None:
        req_modified = ToolRequest(
            request_id=self.request.request_id,
            tool=self.request.tool,
            arguments={"file": "synthetic_different.pdf"},
            purpose=self.request.purpose,
            scenario_id=self.request.scenario_id,
        )
        ev_orig = make_evidence_id(self.request, self.signals, self.policy_version)
        ev_mod = make_evidence_id(req_modified, self.signals, self.policy_version)
        self.assertNotEqual(ev_orig, ev_mod)

    def test_changing_signal_changes_id(self) -> None:
        signals_modified = DecisionSignals(
            prompt_injection=True,
            goal_drift=False,
            sensitive_data_risk="high",
            risk_score=0.9,
            recommended_action="DENY",
            reason="Injection detected",
        )
        ev_orig = make_evidence_id(self.request, self.signals, self.policy_version)
        ev_mod = make_evidence_id(self.request, signals_modified, self.policy_version)
        self.assertNotEqual(ev_orig, ev_mod)

    def test_changing_policy_version_changes_id(self) -> None:
        ev_v1 = make_evidence_id(self.request, self.signals, "v1")
        ev_v2 = make_evidence_id(self.request, self.signals, "v2")
        self.assertNotEqual(ev_v1, ev_v2)


class TestDecideSkeleton(unittest.TestCase):
    """Test decide skeleton, constants, and Decision response shape."""

    def setUp(self) -> None:
        self.request = ToolRequest(
            request_id="req-201",
            tool="summarize_document",
            arguments={"file": "confidential_file.pdf", "recipient": "secret@target.edu"},
            purpose="Analyze document",
            scenario_id="scen-02",
        )
        self.signals = DecisionSignals(
            prompt_injection=False,
            goal_drift=False,
            sensitive_data_risk="low",
            risk_score=0.1,
            recommended_action="ALLOW",
            reason="Advisory ok",
        )

    def test_constants_defined(self) -> None:
        self.assertEqual(RULE_R1, "R1")
        self.assertEqual(RULE_R2, "R2")
        self.assertEqual(RULE_R3, "R3")
        self.assertEqual(RULE_R4, "R4")
        self.assertEqual(RULE_R5, "R5")
        self.assertEqual(RULE_R6, "R6")
        self.assertEqual(RULE_R7, "R7")
        self.assertTrue(isinstance(REASON_R7_DEFAULT_HOLD, str) and len(REASON_R7_DEFAULT_HOLD) > 0)

    def test_decide_returns_r7_hold_shape(self) -> None:
        decision = decide(self.request, self.signals)
        self.assertIsInstance(decision, Decision)
        self.assertEqual(decision.decision, HOLD)
        self.assertEqual(decision.rule_id, RULE_R7)
        self.assertEqual(decision.request_id, "req-201")
        self.assertEqual(decision.policy_version, POLICY_VERSION)
        self.assertEqual(decision.reason, REASON_R7_DEFAULT_HOLD)
        expected_ev = make_evidence_id(self.request, self.signals, POLICY_VERSION)
        self.assertEqual(decision.evidence_id, expected_ev)

        # Ensure to_dict adheres strictly to decision schema (no rule_id or risk_signals inside to_dict)
        d_dict = decision.to_dict()
        self.assertEqual(set(d_dict.keys()), {"request_id", "decision", "evidence_id", "reason", "policy_version"})

    def test_decide_with_explicit_policy(self) -> None:
        decision = decide(self.request, self.signals, policy=POLICY_V1)
        self.assertEqual(decision.decision, HOLD)
        self.assertEqual(decision.rule_id, RULE_R7)

    def test_decide_resolves_get_policy_when_none(self) -> None:
        with self.assertRaises(KeyError):
            decide(self.request, self.signals, policy_version="unknown_v99", policy=None)

    def test_reasons_never_include_argument_values(self) -> None:
        decision = decide(self.request, self.signals)
        for arg_val in ("confidential_file.pdf", "secret@target.edu"):
            self.assertNotIn(arg_val, decision.reason)


class TestEnforceR1AndR2(unittest.TestCase):
    """Test R1 (unallowed tool) and R2 (external destination + high risk) rules."""

    def setUp(self) -> None:
        self.signals_low = DecisionSignals(
            prompt_injection=False,
            goal_drift=False,
            sensitive_data_risk="low",
            risk_score=0.1,
            recommended_action="ALLOW",
            reason="Low risk",
        )
        self.signals_high = DecisionSignals(
            prompt_injection=False,
            goal_drift=False,
            sensitive_data_risk="high",
            risk_score=0.8,
            recommended_action="DENY",
            reason="High sensitive risk",
        )

    def test_export_records_denied_by_r1(self) -> None:
        req = ToolRequest(
            request_id="req-r1",
            tool="export_records",
            arguments={"query": "all"},
            purpose="Export records",
            scenario_id="scen-r1",
        )
        dec = decide(req, self.signals_low)
        self.assertEqual(dec.decision, DENY)
        self.assertEqual(dec.rule_id, RULE_R1)
        self.assertEqual(dec.reason, REASON_R1_UNALLOWED_TOOL)

    def test_external_destination_high_risk_denied_by_r2(self) -> None:
        req = ToolRequest(
            request_id="req-r2",
            tool="send_email",
            arguments={"recipient": "attacker@evil.com", "body": "export"},
            purpose="Send report",
            scenario_id="scen-r2",
        )
        dec = decide(req, self.signals_high)
        self.assertEqual(dec.decision, DENY)
        self.assertEqual(dec.rule_id, RULE_R2)
        self.assertEqual(dec.reason, REASON_R2_EXTERNAL_SENSITIVE)

    def test_internal_destination_high_risk_not_denied_by_r2(self) -> None:
        req = ToolRequest(
            request_id="req-r2-int",
            tool="send_email",
            arguments={"recipient": "dean@example.edu", "body": "export"},
            purpose="Send internal report",
            scenario_id="scen-r2",
        )
        dec = decide(req, self.signals_high)
        self.assertNotEqual(dec.rule_id, RULE_R2)
        self.assertEqual(dec.decision, HOLD)

    def test_signals_none_does_not_trigger_r2(self) -> None:
        req = ToolRequest(
            request_id="req-r2-none",
            tool="send_email",
            arguments={"recipient": "attacker@evil.com"},
            purpose="Send external",
            scenario_id="scen-r2",
        )
        dec = decide(req, None)
        self.assertNotEqual(dec.rule_id, RULE_R2)
        self.assertEqual(dec.decision, HOLD)


if __name__ == "__main__":
    unittest.main()

