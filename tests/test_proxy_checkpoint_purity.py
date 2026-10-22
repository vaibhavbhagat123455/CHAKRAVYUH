"""Tests proving purity, determinism, and AI non-authority in checkpoint decide()."""

import builtins
import copy
import random
import socket
import time
import unittest
from unittest.mock import patch

from core.contracts import POLICY_VERSION
from proxy.checkpoint import (
    RULE_R1,
    RULE_R2,
    RULE_R3,
    decide,
)
from proxy.models import DENY, DecisionSignals, ToolRequest
from proxy.policy import POLICY_V1


class TestCheckpointPurityAndDeterminism(unittest.TestCase):
    """Test pure execution, side-effect isolation, and input immutability."""

    def setUp(self) -> None:
        self.request = ToolRequest(
            request_id="req-pure-01",
            tool="summarize_document",
            arguments={"file": "synthetic_report.pdf"},
            purpose="Summarize report",
            scenario_id="scen-pure-01",
        )
        self.signals = DecisionSignals(
            prompt_injection=False,
            goal_drift=False,
            sensitive_data_risk="low",
            risk_score=0.1,
            recommended_action="ALLOW",
            reason="Benign summary",
        )

    def test_100_repeated_calls_identical(self) -> None:
        first = decide(self.request, self.signals, policy=POLICY_V1)
        for _ in range(99):
            nxt = decide(self.request, self.signals, policy=POLICY_V1)
            self.assertEqual(first, nxt)
            self.assertEqual(first.to_dict(), nxt.to_dict())

    def test_purity_with_patched_side_effects(self) -> None:
        def raise_side_effect(*args, **kwargs):
            raise RuntimeError("Forbidden side-effect executed in decide()")

        with patch.object(time, "time", side_effect=raise_side_effect), \
             patch.object(random, "random", side_effect=raise_side_effect), \
             patch.object(socket, "socket", side_effect=raise_side_effect), \
             patch.object(builtins, "open", side_effect=raise_side_effect):
            # decide must execute smoothly without invoking any side-effect
            decision = decide(self.request, self.signals, policy=POLICY_V1)
            self.assertIsNotNone(decision)
            self.assertEqual(decision.request_id, "req-pure-01")

    def test_ai_recommended_action_cannot_override_r1_to_r3(self) -> None:
        # R1: Unallowed tool with AI recommended_action="ALLOW"
        req_r1 = ToolRequest("r1-ai", "export_records", {"filter": "all"}, "Export", "s1")
        sig_r1 = DecisionSignals(False, False, "low", 0.05, "ALLOW", "AI suggests allow")
        dec_r1 = decide(req_r1, sig_r1, policy=POLICY_V1)
        self.assertEqual(dec_r1.decision, DENY)
        self.assertEqual(dec_r1.rule_id, RULE_R1)

        # R2: External destination + high risk with AI recommended_action="ALLOW"
        req_r2 = ToolRequest("r2-ai", "send_email", {"recipient": "attacker@evil.com"}, "Send", "s1")
        sig_r2 = DecisionSignals(False, False, "high", 0.2, "ALLOW", "AI suggests allow")
        dec_r2 = decide(req_r2, sig_r2, policy=POLICY_V1)
        self.assertEqual(dec_r2.decision, DENY)
        self.assertEqual(dec_r2.rule_id, RULE_R2)

        # R3: High-impact tool + threat with AI recommended_action="ALLOW"
        req_r3 = ToolRequest("r3-ai", "send_email", {"recipient": "dean@example.edu"}, "Send", "s1")
        sig_r3 = DecisionSignals(True, False, "low", 0.1, "ALLOW", "AI claims false positive")
        dec_r3 = decide(req_r3, sig_r3, policy=POLICY_V1)
        self.assertEqual(dec_r3.decision, DENY)
        self.assertEqual(dec_r3.rule_id, RULE_R3)

    def test_decision_to_dict_has_exactly_five_keys(self) -> None:
        dec = decide(self.request, self.signals, policy=POLICY_V1)
        d = dec.to_dict()
        expected_keys = {"request_id", "decision", "evidence_id", "reason", "policy_version"}
        self.assertEqual(set(d.keys()), expected_keys)
        self.assertEqual(len(d), 5)

    def test_inputs_not_mutated(self) -> None:
        req_copy = copy.deepcopy(self.request.to_dict())
        sig_copy = copy.deepcopy(self.signals.to_dict())

        decide(self.request, self.signals, policy=POLICY_V1)

        self.assertEqual(self.request.to_dict(), req_copy)
        self.assertEqual(self.signals.to_dict(), sig_copy)


if __name__ == "__main__":
    unittest.main()
