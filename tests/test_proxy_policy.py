"""Tests for PolicyConfig, policy v1 configuration, and policy predicates."""

from dataclasses import FrozenInstanceError
import json
import os
from pathlib import Path
import tempfile
import unittest

from core.contracts import POLICY_VERSION
from proxy.policy import (
    POLICIES,
    POLICY_V1,
    PolicyConfig,
    destination_of,
    get_policy,
    is_allowed_tool,
    is_external_destination,
    is_high_impact,
    is_safe_summary,
    load_policy,
    requires_approval,
)


class TestPolicyConfig(unittest.TestCase):
    """Test PolicyConfig frozen dataclass, validation, and registry."""

    def test_policy_v1_exact_values(self) -> None:
        self.assertEqual(POLICY_V1.policy_version, POLICY_VERSION)
        self.assertEqual(
            POLICY_V1.allowed_tools,
            frozenset({"summarize_document", "send_email", "transfer_records"}),
        )
        self.assertEqual(
            POLICY_V1.high_impact_tools,
            frozenset({"send_email", "transfer_records"}),
        )
        self.assertEqual(
            POLICY_V1.approval_required_tools,
            frozenset({"transfer_records"}),
        )
        self.assertEqual(
            POLICY_V1.safe_domains,
            frozenset({"example.edu", "college.example"}),
        )
        self.assertEqual(
            POLICY_V1.sensitive_categories,
            frozenset({"student_record", "identity_data", "confidential_report"}),
        )
        self.assertEqual(
            POLICY_V1.destination_argument_keys,
            ("recipient", "destination", "to"),
        )
        self.assertEqual(
            POLICY_V1.public_file_markers,
            ("synthetic_", "public_"),
        )
        self.assertNotIn("export_records", POLICY_V1.allowed_tools)

    def test_policy_config_is_frozen(self) -> None:
        with self.assertRaises((FrozenInstanceError, AttributeError)):
            POLICY_V1.policy_version = "modified"  # type: ignore[misc]

    def test_high_impact_not_subset_raises_value_error(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            PolicyConfig(
                policy_version="test",
                allowed_tools=frozenset({"tool_a"}),
                high_impact_tools=frozenset({"tool_a", "tool_b"}),
                approval_required_tools=frozenset({"tool_a"}),
                safe_domains=frozenset(),
                sensitive_categories=frozenset(),
                destination_argument_keys=(),
                public_file_markers=(),
            )
        self.assertIn("high_impact_tools", str(ctx.exception))

    def test_approval_required_not_subset_raises_value_error(self) -> None:
        with self.assertRaises(ValueError) as ctx:
            PolicyConfig(
                policy_version="test",
                allowed_tools=frozenset({"tool_a"}),
                high_impact_tools=frozenset({"tool_a"}),
                approval_required_tools=frozenset({"tool_b"}),
                safe_domains=frozenset(),
                sensitive_categories=frozenset(),
                destination_argument_keys=(),
                public_file_markers=(),
            )
        self.assertIn("approval_required_tools", str(ctx.exception))

    def test_get_policy_success(self) -> None:
        policy = get_policy("v1")
        self.assertIs(policy, POLICY_V1)
        self.assertIn("v1", POLICIES)

    def test_get_policy_unknown_version_raises_key_error(self) -> None:
        with self.assertRaises(KeyError) as ctx:
            get_policy("nonexistent_v99")
        self.assertIn("nonexistent_v99", str(ctx.exception))


class TestPolicyPredicates(unittest.TestCase):
    """Test policy predicates evaluated against PolicyConfig."""

    def setUp(self) -> None:
        self.policy = POLICY_V1

    def test_is_allowed_tool(self) -> None:
        self.assertTrue(is_allowed_tool("summarize_document", self.policy))
        self.assertTrue(is_allowed_tool("send_email", self.policy))
        self.assertTrue(is_allowed_tool("transfer_records", self.policy))
        self.assertFalse(is_allowed_tool("export_records", self.policy))
        self.assertFalse(is_allowed_tool("delete_database", self.policy))
        self.assertFalse(is_allowed_tool("", self.policy))

    def test_is_high_impact(self) -> None:
        self.assertTrue(is_high_impact("send_email", self.policy))
        self.assertTrue(is_high_impact("transfer_records", self.policy))
        self.assertFalse(is_high_impact("summarize_document", self.policy))
        self.assertFalse(is_high_impact("export_records", self.policy))

    def test_requires_approval(self) -> None:
        self.assertTrue(requires_approval("transfer_records", self.policy))
        self.assertFalse(requires_approval("send_email", self.policy))
        self.assertFalse(requires_approval("summarize_document", self.policy))

    def test_destination_of(self) -> None:
        self.assertEqual(destination_of({"recipient": "alice@example.edu"}, self.policy), "alice@example.edu")
        self.assertEqual(destination_of({"destination": "bob@college.example"}, self.policy), "bob@college.example")
        self.assertEqual(destination_of({"to": "charlie@example.edu"}, self.policy), "charlie@example.edu")
        args = {"recipient": "primary@example.edu", "destination": "secondary@example.edu", "to": "third@example.edu"}
        self.assertEqual(destination_of(args, self.policy), "primary@example.edu")
        self.assertEqual(destination_of({"recipient": "  ", "destination": "b@example.edu"}, self.policy), "b@example.edu")
        self.assertIsNone(destination_of({"file": "data.csv"}, self.policy))
        self.assertIsNone(destination_of({}, self.policy))

    def test_is_external_destination(self) -> None:
        self.assertFalse(is_external_destination(None, self.policy))
        self.assertFalse(is_external_destination("", self.policy))
        self.assertFalse(is_external_destination("   ", self.policy))
        self.assertFalse(is_external_destination("dean@example.edu", self.policy))
        self.assertFalse(is_external_destination("DEAN@EXAMPLE.EDU", self.policy))
        self.assertFalse(is_external_destination("admin@college.example", self.policy))
        self.assertFalse(is_external_destination("cs@dept.example.edu", self.policy))
        self.assertTrue(is_external_destination("attacker@evil.com", self.policy))
        self.assertTrue(is_external_destination("attacker@example.edu.evil.com", self.policy))
        self.assertTrue(is_external_destination("example.edu.evil.com", self.policy))
        self.assertFalse(is_external_destination("example.edu", self.policy))
        self.assertFalse(is_external_destination("COLLEGE.EXAMPLE", self.policy))
        self.assertTrue(is_external_destination("evil.com", self.policy))
        self.assertTrue(is_external_destination("unknown_endpoint", self.policy))

    def test_is_safe_summary(self) -> None:
        self.assertTrue(is_safe_summary({"file": "synthetic_report.pdf"}, self.policy))
        self.assertTrue(is_safe_summary({"path": "public_bulletin.txt"}, self.policy))
        self.assertTrue(is_safe_summary({"file": "SYNTHETIC_ANNOUNCEMENT.PDF"}, self.policy))
        self.assertFalse(is_safe_summary({"file": "internal_memo.docx"}, self.policy))
        self.assertFalse(is_safe_summary({}, self.policy))
        self.assertFalse(is_safe_summary({"file": ""}, self.policy))
        self.assertFalse(is_safe_summary({"file": "synthetic_data.pdf", "category": "confidential_report"}, self.policy))
        self.assertFalse(is_safe_summary({"file": "synthetic_student_record.csv"}, self.policy))


class TestPolicyLoaderAndDocumentation(unittest.TestCase):
    """Test policy JSON loader and R1-R7 table documentation."""

    def test_load_policy_v1_example_equals_policy_v1(self) -> None:
        path = Path(__file__).resolve().parent.parent / "docs" / "policy_v1.example.json"
        loaded = load_policy(path)
        self.assertEqual(loaded, POLICY_V1)

    def test_load_policy_missing_keys(self) -> None:
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            json.dump({"policy_version": "v1"}, f)
            fname = f.name
        self.addCleanup(lambda: os.remove(fname))
        with self.assertRaises(ValueError) as ctx:
            load_policy(fname)
        self.assertIn("Missing required keys", str(ctx.exception))

    def test_load_policy_unknown_keys(self) -> None:
        path = Path(__file__).resolve().parent.parent / "docs" / "policy_v1.example.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["unexpected_key"] = "bad"
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            json.dump(data, f)
            fname = f.name
        self.addCleanup(lambda: os.remove(fname))
        with self.assertRaises(ValueError) as ctx:
            load_policy(fname)
        self.assertIn("Unknown keys", str(ctx.exception))

    def test_load_policy_wrong_types(self) -> None:
        path = Path(__file__).resolve().parent.parent / "docs" / "policy_v1.example.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        data["allowed_tools"] = "not_a_list"
        with tempfile.NamedTemporaryFile("w", delete=False) as f:
            json.dump(data, f)
            fname = f.name
        self.addCleanup(lambda: os.remove(fname))
        with self.assertRaises(ValueError) as ctx:
            load_policy(fname)
        self.assertIn("Invalid type", str(ctx.exception))

    def test_r1_to_r7_table_in_policy_docstring(self) -> None:
        import proxy.policy as pol
        doc = pol.__doc__ or ""
        for r_id in ("R1", "R2", "R3", "R4", "R5", "R6", "R7"):
            self.assertIn(r_id, doc)


if __name__ == "__main__":
    unittest.main()
