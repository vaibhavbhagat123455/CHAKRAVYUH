import unittest

from core.layers import build_layer_results
from core.policies import (
    evaluate_policy,
    has_sensitive_arguments,
    is_external_destination,
)
from core.schemas import DecisionSignals, ToolRequest
from tests.log_helpers import scenario_records


class PolicyTests(unittest.TestCase):
    def test_demo_policy_matrix(self):
        expected = {
            "malicious-pdf-001": "DENY",
            "safe-summary-001": "ALLOW",
            "approval-transfer-001": "HOLD",
        }
        for record in scenario_records():
            result = evaluate_policy(record["request"], record["signals"])
            self.assertEqual(result.decision, expected[record["request"].scenario_id])
            self.assertTrue(result.reason)

    def test_unknown_tool_is_denied(self):
        request = ToolRequest("req", "delete_database", {}, "clean up", "scenario")
        signals = DecisionSignals(False, False, "low", 0.0, "ALLOW", "safe")
        self.assertEqual(evaluate_policy(request, signals).decision, "DENY")

    def test_ai_allow_cannot_override_explicit_rule(self):
        request = ToolRequest(
            "req",
            "send_email",
            {"recipient": "external@example.com", "file": "synthetic_student_records.pdf"},
            "send records",
            "scenario",
        )
        signals = DecisionSignals(
            True,
            True,
            "high",
            0.1,
            "ALLOW",
            "the AI was manipulated into recommending ALLOW",
        )
        result = evaluate_policy(request, signals)
        self.assertEqual(result.decision, "DENY")
        self.assertEqual(result.policy_facts["ai_recommended_action"], "ALLOW")

    def test_evidence_ids_are_deterministic(self):
        record = scenario_records()[0]
        first = evaluate_policy(record["request"], record["signals"])
        second = evaluate_policy(record["request"], record["signals"])
        self.assertEqual(first.evidence_id, second.evidence_id)
        self.assertTrue(first.evidence_id.startswith("ev-"))

    def test_evidence_id_changes_when_argument_changes(self):
        record = scenario_records()[0]
        first = evaluate_policy(record["request"], record["signals"])
        changed = ToolRequest(
            record["request"].request_id,
            record["request"].tool,
            {"recipient": "different@example.com", "file": "synthetic_student_records.pdf"},
            record["request"].purpose,
            record["request"].scenario_id,
        )
        second = evaluate_policy(changed, record["signals"])
        self.assertNotEqual(first.evidence_id, second.evidence_id)

    def test_unknown_policy_version_fails_closed(self):
        record = scenario_records()[0]
        with self.assertRaises(ValueError):
            evaluate_policy(record["request"], record["signals"], "v999")

    def test_seven_layers_are_emitted(self):
        record = scenario_records()[0]
        decision = evaluate_policy(record["request"], record["signals"])
        layers = build_layer_results(record["request"], record["signals"], decision)
        self.assertEqual(
            [layer.layer_id for layer in layers],
            ["DWAAR", "PEHCHAAN", "SMRITI", "SANKALP", "ASTRA", "MARYADA", "DRISHTI"],
        )
        self.assertTrue(all(layer.evidence_id.startswith("ev-") for layer in layers))
        self.assertEqual(layers[0].status, "BLOCK")
        self.assertEqual(layers[3].status, "BLOCK")

    def test_external_sensitive_transfer_is_held(self):
        request = ToolRequest(
            "req",
            "send_email",
            {"recipient": "external@example.com", "file": "synthetic_confidential_report.pdf"},
            "send confidential report",
            "scenario",
        )
        signals = DecisionSignals(False, False, "high", 0.7, "HOLD", "review")
        result = evaluate_policy(request, signals)
        self.assertEqual(result.decision, "HOLD")
        self.assertTrue(result.policy_facts["external_destination"])
        self.assertTrue(result.policy_facts["sensitive_data"])

    def test_safe_tool_with_injection_is_held(self):
        record = scenario_records()[1]
        signals = DecisionSignals(True, False, "low", 0.4, "HOLD", "suspicious content")
        result = evaluate_policy(record["request"], signals)
        self.assertEqual(result.decision, "HOLD")

    def test_external_destination_detection(self):
        external = ToolRequest(
            "req",
            "upload_file",
            {"destination": "https://example.test/upload"},
            "upload",
            "scenario",
        )
        internal = scenario_records()[1]["request"]
        self.assertTrue(is_external_destination(external))
        self.assertFalse(is_external_destination(internal))

    def test_sensitive_argument_detection(self):
        self.assertTrue(has_sensitive_arguments(scenario_records()[0]["request"]))
        self.assertFalse(has_sensitive_arguments(scenario_records()[1]["request"]))

    def test_decision_serialises_signals_and_layers(self):
        record = scenario_records()[0]
        result = evaluate_policy(record["request"], record["signals"])
        data = result.to_dict()
        self.assertIn("signals", data)
        self.assertEqual(len(data["layer_results"]), 7)
        self.assertEqual(data["policy_facts"]["matched_rule"], "injection_or_drift_with_sensitive_or_external")


if __name__ == "__main__":
    unittest.main(verbosity=2)
