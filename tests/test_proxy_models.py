"""Tests for proxy data models."""

import json
from pathlib import Path
import unittest

from core.contracts import DECISIONS, POLICY_VERSION
from proxy.models import ALLOW, DENY, HOLD, Decision, ToolRequest


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


if __name__ == "__main__":
    unittest.main()
