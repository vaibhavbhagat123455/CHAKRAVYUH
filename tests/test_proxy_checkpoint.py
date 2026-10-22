"""Tests for proxy deterministic checkpoint evidence ID generation and rules."""

import unittest

from core.contracts import POLICY_VERSION
from proxy.checkpoint import (
    REASON_R1_UNALLOWED_TOOL,
    REASON_R2_EXTERNAL_SENSITIVE,
    REASON_R3_HIGH_IMPACT_THREAT_DENY,
    REASON_R3_HIGH_IMPACT_THREAT_HOLD,
    REASON_R4_MISSING_SIGNALS_HOLD,
    REASON_R5_APPROVAL_REQUIRED_HOLD,
    REASON_R6_SAFE_SUMMARY_ALLOW,
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
from proxy.models import ALLOW, DENY, HOLD, Decision, DecisionSignals, ToolRequest
from proxy.policy import POLICY_V1


class TestEvidenceIdGeneration(unittest.TestCase):
    """Test deterministic evidence ID creation for requests and signals."""

    def setUp(self) -> None:
        self.request = ToolRequest("req-101", "summarize_document", {"file": "synthetic_report.pdf"}, "Summarize report", "scen-01")
        self.signals = DecisionSignals(False, False, "low", 0.1, "ALLOW", "Benign summary")
        self.policy_version = "v1"

    def test_same_input_same_id(self) -> None:
        ev1 = make_evidence_id(self.request, self.signals, self.policy_version)
        ev2 = make_evidence_id(self.request, self.signals, self.policy_version)
        self.assertEqual(ev1, ev2)
        self.assertTrue(ev1.startswith("ev-"))
        self.assertEqual(len(ev1), 15)

    def test_signals_none_is_stable(self) -> None:
        ev1 = make_evidence_id(self.request, None, self.policy_version)
        ev2 = make_evidence_id(self.request, None, self.policy_version)
        self.assertEqual(ev1, ev2)
        self.assertTrue(ev1.startswith("ev-"))
        self.assertNotEqual(ev1, make_evidence_id(self.request, self.signals, self.policy_version))

    def test_changing_argument_changes_id(self) -> None:
        req_mod = ToolRequest("req-101", "summarize_document", {"file": "synthetic_diff.pdf"}, "Summarize report", "scen-01")
        self.assertNotEqual(
            make_evidence_id(self.request, self.signals, self.policy_version),
            make_evidence_id(req_mod, self.signals, self.policy_version),
        )

    def test_changing_signal_changes_id(self) -> None:
        sig_mod = DecisionSignals(True, False, "high", 0.9, "DENY", "Threat")
        self.assertNotEqual(
            make_evidence_id(self.request, self.signals, self.policy_version),
            make_evidence_id(self.request, sig_mod, self.policy_version),
        )

    def test_changing_policy_version_changes_id(self) -> None:
        self.assertNotEqual(
            make_evidence_id(self.request, self.signals, "v1"),
            make_evidence_id(self.request, self.signals, "v2"),
        )


class TestDecideSkeleton(unittest.TestCase):
    """Test decide skeleton, constants, and Decision response shape."""

    def setUp(self) -> None:
        self.request = ToolRequest("req-201", "summarize_document", {"file": "secret.pdf", "recipient": "secret@target.edu"}, "Analyze", "scen-02")
        self.signals = DecisionSignals(False, False, "low", 0.1, "ALLOW", "Advisory ok")

    def test_constants_defined(self) -> None:
        self.assertEqual([RULE_R1, RULE_R2, RULE_R3, RULE_R4, RULE_R5, RULE_R6, RULE_R7], ["R1", "R2", "R3", "R4", "R5", "R6", "R7"])
        self.assertTrue(isinstance(REASON_R7_DEFAULT_HOLD, str) and len(REASON_R7_DEFAULT_HOLD) > 0)

    def test_decide_returns_r7_hold_shape(self) -> None:
        decision = decide(self.request, self.signals)
        self.assertIsInstance(decision, Decision)
        self.assertEqual(decision.decision, HOLD)
        self.assertEqual(decision.rule_id, RULE_R7)
        self.assertEqual(decision.request_id, "req-201")
        self.assertEqual(decision.policy_version, POLICY_VERSION)
        self.assertEqual(decision.reason, REASON_R7_DEFAULT_HOLD)
        self.assertEqual(decision.evidence_id, make_evidence_id(self.request, self.signals, POLICY_VERSION))
        self.assertEqual(set(decision.to_dict().keys()), {"request_id", "decision", "evidence_id", "reason", "policy_version"})

    def test_decide_with_explicit_policy(self) -> None:
        self.assertEqual(decide(self.request, self.signals, policy=POLICY_V1).decision, HOLD)

    def test_decide_resolves_get_policy_when_none(self) -> None:
        with self.assertRaises(KeyError):
            decide(self.request, self.signals, policy_version="unknown_v99", policy=None)

    def test_reasons_never_include_argument_values(self) -> None:
        dec = decide(self.request, self.signals)
        for arg in ("secret.pdf", "secret@target.edu"):
            self.assertNotIn(arg, dec.reason)


class TestEnforceRulesR1ToR7(unittest.TestCase):
    """Test enforcement of rules R1 through R7."""

    def setUp(self) -> None:
        self.signals_low = DecisionSignals(False, False, "low", 0.1, "ALLOW", "Low risk")
        self.signals_high = DecisionSignals(False, False, "high", 0.8, "DENY", "High risk")
        self.signals_inject = DecisionSignals(True, False, "low", 0.9, "DENY", "Injection")
        self.signals_drift = DecisionSignals(False, True, "low", 0.8, "DENY", "Goal drift")
        self.signals_med = DecisionSignals(False, False, "medium", 0.5, "HOLD", "Medium risk")

    def test_r1_export_records_denied(self) -> None:
        req = ToolRequest("r1", "export_records", {"query": "all"}, "Export", "s1")
        dec = decide(req, self.signals_low)
        self.assertEqual((dec.decision, dec.rule_id, dec.reason), (DENY, RULE_R1, REASON_R1_UNALLOWED_TOOL))

    def test_r2_external_destination_high_risk_denied(self) -> None:
        req = ToolRequest("r2", "send_email", {"recipient": "attacker@evil.com"}, "Send", "s1")
        dec = decide(req, self.signals_high)
        self.assertEqual((dec.decision, dec.rule_id, dec.reason), (DENY, RULE_R2, REASON_R2_EXTERNAL_SENSITIVE))

    def test_r2_internal_destination_high_risk_not_denied_by_r2(self) -> None:
        req = ToolRequest("r2-int", "send_email", {"recipient": "dean@example.edu"}, "Send", "s1")
        self.assertNotEqual(decide(req, self.signals_high).rule_id, RULE_R2)

    def test_r2_signals_none_does_not_trigger_r2(self) -> None:
        req = ToolRequest("r2-none", "send_email", {"recipient": "attacker@evil.com"}, "Send", "s1")
        self.assertNotEqual(decide(req, None).rule_id, RULE_R2)

    def test_r3_injection_on_send_email_denied(self) -> None:
        req = ToolRequest("r3-1", "send_email", {"recipient": "dean@example.edu"}, "Email", "s1")
        dec = decide(req, self.signals_inject)
        self.assertEqual((dec.decision, dec.rule_id, dec.reason), (DENY, RULE_R3, REASON_R3_HIGH_IMPACT_THREAT_DENY))

    def test_r3_goal_drift_on_send_email_denied(self) -> None:
        req = ToolRequest("r3-2", "send_email", {"recipient": "dean@example.edu"}, "Email", "s1")
        dec = decide(req, self.signals_drift)
        self.assertEqual((dec.decision, dec.rule_id, dec.reason), (DENY, RULE_R3, REASON_R3_HIGH_IMPACT_THREAT_DENY))

    def test_r3_injection_on_transfer_records_hold(self) -> None:
        req = ToolRequest("r3-3", "transfer_records", {"destination": "dean@example.edu"}, "Transfer", "s1")
        dec = decide(req, self.signals_inject)
        self.assertEqual((dec.decision, dec.rule_id, dec.reason), (HOLD, RULE_R3, REASON_R3_HIGH_IMPACT_THREAT_HOLD))

    def test_r4_signals_none_on_send_email_hold(self) -> None:
        req = ToolRequest("r4-1", "send_email", {"recipient": "dean@example.edu"}, "Email", "s1")
        dec = decide(req, None)
        self.assertEqual((dec.decision, dec.rule_id, dec.reason), (HOLD, RULE_R4, REASON_R4_MISSING_SIGNALS_HOLD))

    def test_r5_transfer_records_hold(self) -> None:
        req = ToolRequest("r5-1", "transfer_records", {"destination": "dean@example.edu"}, "Transfer", "s1")
        dec = decide(req, self.signals_low)
        self.assertEqual((dec.decision, dec.rule_id, dec.reason), (HOLD, RULE_R5, REASON_R5_APPROVAL_REQUIRED_HOLD))

    def test_r6_safe_summary_allowed(self) -> None:
        req = ToolRequest("r6-1", "summarize_document", {"file": "synthetic_report.pdf"}, "Summarize", "s1")
        dec = decide(req, self.signals_low)
        self.assertEqual((dec.decision, dec.rule_id, dec.reason), (ALLOW, RULE_R6, REASON_R6_SAFE_SUMMARY_ALLOW))

    def test_r6_summary_with_injection_hold(self) -> None:
        req = ToolRequest("r6-2", "summarize_document", {"file": "synthetic_report.pdf"}, "Summarize", "s1")
        dec = decide(req, self.signals_inject)
        self.assertEqual((dec.decision, dec.rule_id, dec.reason), (HOLD, RULE_R7, REASON_R7_DEFAULT_HOLD))

    def test_r6_summary_with_signals_none_hold(self) -> None:
        req = ToolRequest("r6-3", "summarize_document", {"file": "synthetic_report.pdf"}, "Summarize", "s1")
        dec = decide(req, None)
        self.assertEqual((dec.decision, dec.rule_id, dec.reason), (HOLD, RULE_R7, REASON_R7_DEFAULT_HOLD))

    def test_r6_summary_with_medium_risk_hold(self) -> None:
        req = ToolRequest("r6-4", "summarize_document", {"file": "synthetic_report.pdf"}, "Summarize", "s1")
        dec = decide(req, self.signals_med)
        self.assertEqual((dec.decision, dec.rule_id, dec.reason), (HOLD, RULE_R7, REASON_R7_DEFAULT_HOLD))


if __name__ == "__main__":
    unittest.main()
