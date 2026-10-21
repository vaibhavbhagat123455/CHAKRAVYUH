import json
import unittest
from pathlib import Path

from core.contracts import DECISIONS, canonical_json, validate_decision, validate_event_type


class SharedContractsTests(unittest.TestCase):
    def test_decisions_are_frozen_and_exact(self):
        self.assertEqual(DECISIONS, {"ALLOW", "HOLD", "DENY"})
        for value in DECISIONS:
            self.assertEqual(validate_decision(value), value)
        with self.assertRaises(ValueError):
            validate_decision("EXECUTE")

    def test_canonical_json_is_order_independent(self):
        self.assertEqual(canonical_json({"b": 2, "a": 1}), '{"a":1,"b":2}')

    def test_event_type_validation(self):
        self.assertEqual(validate_event_type("CHECKPOINT_DECISION"), "CHECKPOINT_DECISION")
        with self.assertRaises(ValueError):
            validate_event_type("UNKNOWN")

    def test_schema_files_are_valid_json(self):
        root = Path(__file__).parents[1]
        for path in (root / "schemas").glob("*.schema.json"):
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(data["type"], "object")
            self.assertIn("required", data)


if __name__ == "__main__":
    unittest.main(verbosity=2)
