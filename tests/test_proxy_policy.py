"""Tests for PolicyConfig and policy v1 configuration."""

from dataclasses import FrozenInstanceError
import unittest

from core.contracts import POLICY_VERSION
from proxy.policy import POLICIES, POLICY_V1, PolicyConfig, get_policy


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


if __name__ == "__main__":
    unittest.main()
