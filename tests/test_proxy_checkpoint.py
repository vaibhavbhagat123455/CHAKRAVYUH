"""Tests for proxy deterministic checkpoint evidence ID generation."""

import unittest

from proxy.checkpoint import make_evidence_id
from proxy.models import DecisionSignals, ToolRequest


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
        # Must differ from when signals is present
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


if __name__ == "__main__":
    unittest.main()
