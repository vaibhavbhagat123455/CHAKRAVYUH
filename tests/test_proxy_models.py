"""Tests for proxy data models."""

import json
from pathlib import Path
import unittest

from core.contracts import DECISIONS, POLICY_VERSION
from proxy.models import (
    ALLOW,
    BLOCK,
    DENY,
    FLAG,
    HOLD,
    PASS,
    ApprovalResult,
    Decision,
    DecisionSignals,
    LayerResult,
    ToolRequest,
)


class TestToolRequest(unittest.TestCase):
    """Test ToolRequest validation, serialization, and immutability."""

    def setUp(self) -> None:
        self.valid_payload = {
            "request_id": "req-001",
            "tool": "summarize_document",
            "arguments": {"file": "circular.pdf"},
            "purpose": "Summarize circular notice",
            "scenario_id": "safe-001",
        }

    def test_valid_creation_and_to_dict(self) -> None:
        req = ToolRequest.from_dict(self.valid_payload)
        self.assertEqual(req.request_id, "req-001")
        self.assertEqual(req.tool, "summarize_document")
        self.assertEqual(req.arguments, {"file": "circular.pdf"})
        self.assertEqual(req.purpose, "Summarize circular notice")
        self.assertEqual(req.scenario_id, "safe-001")
        self.assertEqual(req.to_dict(), self.valid_payload)

    def test_matches_schema_definition(self) -> None:
        schema_path = Path(__file__).parents[1] / "schemas" / "tool_request.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        req = ToolRequest.from_dict(self.valid_payload)
        d = req.to_dict()
        for field_name in schema["required"]:
            self.assertIn(field_name, d)
        self.assertEqual(set(d.keys()), set(schema["required"]))

    def test_missing_fields_raise_value_error(self) -> None:
        for key in ("request_id", "tool", "arguments", "purpose", "scenario_id"):
            bad_data = dict(self.valid_payload)
            del bad_data[key]
            with self.assertRaises(ValueError) as ctx:
                ToolRequest.from_dict(bad_data)
            self.assertIn("Missing required fields", str(ctx.exception))

    def test_unknown_fields_raise_value_error(self) -> None:
        bad_data = dict(self.valid_payload)
        bad_data["extra_field"] = "unexpected"
        with self.assertRaises(ValueError) as ctx:
            ToolRequest.from_dict(bad_data)
        self.assertIn("Unknown fields", str(ctx.exception))

    def test_empty_string_fields_raise_value_error(self) -> None:
        for key in ("request_id", "tool", "purpose", "scenario_id"):
            for bad_val in ("", "   ", "\t\n"):
                bad_data = dict(self.valid_payload)
                bad_data[key] = bad_val
                with self.assertRaises(ValueError) as ctx:
                    ToolRequest.from_dict(bad_data)
                self.assertIn("must be a non-empty string", str(ctx.exception))

    def test_non_string_fields_raise_value_error(self) -> None:
        for key in ("request_id", "tool", "purpose", "scenario_id"):
            bad_data = dict(self.valid_payload)
            bad_data[key] = 12345
            with self.assertRaises(ValueError) as ctx:
                ToolRequest.from_dict(bad_data)
            self.assertIn("must be a non-empty string", str(ctx.exception))

    def test_non_object_arguments_raise_value_error(self) -> None:
        for bad_args in (None, [1, 2, 3], "arguments_as_str", 100):
            bad_data = dict(self.valid_payload)
            bad_data["arguments"] = bad_args
            with self.assertRaises(ValueError) as ctx:
                ToolRequest.from_dict(bad_data)
            self.assertIn("must be an object/dict", str(ctx.exception))

    def test_non_dict_root_raises_value_error(self) -> None:
        with self.assertRaises(ValueError):
            ToolRequest.from_dict("not-a-dict")  # type: ignore

    def test_is_frozen(self) -> None:
        req = ToolRequest.from_dict(self.valid_payload)
        with self.assertRaises(Exception):
            req.tool = "other"  # type: ignore


class TestDecision(unittest.TestCase):
    """Test Decision model reusing core constants and validating schema compliance."""

    def test_exposed_constants(self) -> None:
        self.assertEqual(ALLOW, "ALLOW")
        self.assertEqual(HOLD, "HOLD")
        self.assertEqual(DENY, "DENY")
        self.assertEqual(DECISIONS, {"ALLOW", "HOLD", "DENY"})
        self.assertEqual(POLICY_VERSION, "v1")

    def test_valid_decision_to_dict_has_exactly_five_schema_keys(self) -> None:
        dec = Decision(
            request_id="req-101",
            decision=ALLOW,
            evidence_id="ev-1234567890ab",
            reason="Safe summary action approved",
            policy_version="v1",
            risk_signals={"prompt_injection": False},
            rule_id="R6",
        )
        d = dec.to_dict()
        expected_keys = {"request_id", "decision", "evidence_id", "reason", "policy_version"}
        self.assertEqual(set(d.keys()), expected_keys)
        self.assertEqual(len(d), 5)
        self.assertNotIn("risk_signals", d)
        self.assertNotIn("rule_id", d)

        # Check against schema file
        schema_path = Path(__file__).parents[1] / "schemas" / "decision.schema.json"
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        self.assertEqual(set(schema["required"]), expected_keys)

    def test_invalid_decision_raises_value_error(self) -> None:
        with self.assertRaises(ValueError):
            Decision(
                request_id="req-101",
                decision="EXECUTE",
                evidence_id="ev-1234567890ab",
                reason="Invalid",
            )

    def test_empty_string_fields_raise_value_error(self) -> None:
        for key in ("request_id", "evidence_id", "reason", "policy_version"):
            kwargs = {
                "request_id": "req-1",
                "decision": ALLOW,
                "evidence_id": "ev-1",
                "reason": "ok",
                "policy_version": "v1",
            }
            kwargs[key] = ""
            with self.assertRaises(ValueError):
                Decision(**kwargs)


class TestLayerResult(unittest.TestCase):
    """Test LayerResult validation and constants."""

    def test_constants(self) -> None:
        self.assertEqual(PASS, "PASS")
        self.assertEqual(FLAG, "FLAG")
        self.assertEqual(BLOCK, "BLOCK")

    def test_valid_layer_result(self) -> None:
        res = LayerResult(
            layer_id="DWAAR",
            status=PASS,
            reason="Tool is allowlisted",
            evidence_id="ev-123",
        )
        self.assertEqual(
            res.to_dict(),
            {
                "layer_id": "DWAAR",
                "status": "PASS",
                "reason": "Tool is allowlisted",
                "evidence_id": "ev-123",
            },
        )

    def test_invalid_status_raises_value_error(self) -> None:
        with self.assertRaises(ValueError):
            LayerResult(
                layer_id="DWAAR",
                status="UNKNOWN",
                reason="test",
                evidence_id="ev-1",
            )


class TestDecisionSignals(unittest.TestCase):
    """Test DecisionSignals validation and serialization."""

    def setUp(self) -> None:
        self.valid_data = {
            "prompt_injection": False,
            "goal_drift": False,
            "sensitive_data_risk": "low",
            "risk_score": 0.15,
            "recommended_action": "ALLOW",
            "reason": "Clean benign input",
        }

    def test_valid_signals(self) -> None:
        sig = DecisionSignals.from_dict(self.valid_data)
        self.assertFalse(sig.prompt_injection)
        self.assertFalse(sig.goal_drift)
        self.assertEqual(sig.sensitive_data_risk, "low")
        self.assertAlmostEqual(sig.risk_score, 0.15)
        self.assertEqual(sig.recommended_action, "ALLOW")
        self.assertEqual(sig.to_dict(), self.valid_data)

    def test_invalid_field_values_raise_value_error(self) -> None:
        # non-bool prompt_injection
        d = dict(self.valid_data)
        d["prompt_injection"] = "true"  # type: ignore
        with self.assertRaises(ValueError):
            DecisionSignals.from_dict(d)

        # invalid sensitive_data_risk
        d = dict(self.valid_data)
        d["sensitive_data_risk"] = "critical"
        with self.assertRaises(ValueError):
            DecisionSignals.from_dict(d)

        # risk score out of range
        d = dict(self.valid_data)
        d["risk_score"] = 1.5
        with self.assertRaises(ValueError):
            DecisionSignals.from_dict(d)

        # recommended_action not in DECISIONS
        d = dict(self.valid_data)
        d["recommended_action"] = "EXECUTE"
        with self.assertRaises(ValueError):
            DecisionSignals.from_dict(d)

        # empty reason
        d = dict(self.valid_data)
        d["reason"] = "   "
        with self.assertRaises(ValueError):
            DecisionSignals.from_dict(d)

        # missing and unknown fields
        del d["reason"]
        with self.assertRaises(ValueError):
            DecisionSignals.from_dict(d)

        d = dict(self.valid_data)
        d["extra"] = 1
        with self.assertRaises(ValueError):
            DecisionSignals.from_dict(d)


class TestApprovalResult(unittest.TestCase):
    """Test ApprovalResult validation and serialization."""

    def test_valid_approval_result(self) -> None:
        appr = ApprovalResult(
            approved=True,
            approval_id="appr-101",
            action_digest="digest-abc",
            reason="OTP verified",
        )
        self.assertEqual(
            appr.to_dict(),
            {
                "approved": True,
                "approval_id": "appr-101",
                "action_digest": "digest-abc",
                "reason": "OTP verified",
            },
        )

    def test_invalid_fields_raise_value_error(self) -> None:
        with self.assertRaises(ValueError):
            ApprovalResult(
                approved="true",  # type: ignore
                approval_id="appr-1",
                action_digest="dig",
                reason="ok",
            )

        with self.assertRaises(ValueError):
            ApprovalResult(
                approved=True,
                approval_id="",
                action_digest="dig",
                reason="ok",
            )


if __name__ == "__main__":
    unittest.main()
