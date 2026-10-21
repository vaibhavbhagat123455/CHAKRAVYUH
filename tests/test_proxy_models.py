"""Tests for proxy data models."""

import json
from pathlib import Path
import unittest

from proxy.models import ToolRequest


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


if __name__ == "__main__":
    unittest.main()
