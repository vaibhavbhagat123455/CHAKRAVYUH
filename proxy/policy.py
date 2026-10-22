"""Security policy configuration and registry for AI Chakravyuh proxy."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Tuple

from core.contracts import POLICY_VERSION


@dataclass(frozen=True)
class PolicyConfig:
    """Immutable security policy configuration governing proxy execution rules."""

    policy_version: str
    allowed_tools: frozenset[str]
    high_impact_tools: frozenset[str]
    approval_required_tools: frozenset[str]
    safe_domains: frozenset[str]
    sensitive_categories: frozenset[str]
    destination_argument_keys: Tuple[str, ...]
    public_file_markers: Tuple[str, ...]

    def __post_init__(self) -> None:
        """Validate that high_impact and approval_required are subsets of allowed."""
        if not isinstance(self.allowed_tools, frozenset):
            object.__setattr__(self, "allowed_tools", frozenset(self.allowed_tools))
        if not isinstance(self.high_impact_tools, frozenset):
            object.__setattr__(self, "high_impact_tools", frozenset(self.high_impact_tools))
        if not isinstance(self.approval_required_tools, frozenset):
            object.__setattr__(self, "approval_required_tools", frozenset(self.approval_required_tools))
        if not isinstance(self.safe_domains, frozenset):
            object.__setattr__(self, "safe_domains", frozenset(self.safe_domains))
        if not isinstance(self.sensitive_categories, frozenset):
            object.__setattr__(self, "sensitive_categories", frozenset(self.sensitive_categories))
        if not isinstance(self.destination_argument_keys, tuple):
            object.__setattr__(self, "destination_argument_keys", tuple(self.destination_argument_keys))
        if not isinstance(self.public_file_markers, tuple):
            object.__setattr__(self, "public_file_markers", tuple(self.public_file_markers))

        if not self.high_impact_tools.issubset(self.allowed_tools):
            unallowed = self.high_impact_tools - self.allowed_tools
            raise ValueError(f"high_impact_tools must be a subset of allowed_tools: {sorted(unallowed)}")

        if not self.approval_required_tools.issubset(self.allowed_tools):
            unallowed = self.approval_required_tools - self.allowed_tools
            raise ValueError(f"approval_required_tools must be a subset of allowed_tools: {sorted(unallowed)}")


# Authoritative v1 security policy configuration
POLICY_V1 = PolicyConfig(
    policy_version=POLICY_VERSION,
    allowed_tools=frozenset({"summarize_document", "send_email", "transfer_records"}),
    high_impact_tools=frozenset({"send_email", "transfer_records"}),
    approval_required_tools=frozenset({"transfer_records"}),
    safe_domains=frozenset({"example.edu", "college.example"}),
    sensitive_categories=frozenset({"student_record", "identity_data", "confidential_report"}),
    destination_argument_keys=("recipient", "destination", "to"),
    public_file_markers=("synthetic_", "public_"),
)

POLICIES: Dict[str, PolicyConfig] = {
    POLICY_V1.policy_version: POLICY_V1,
}


def get_policy(version: str) -> PolicyConfig:
    """Retrieve PolicyConfig by policy_version identifier.

    Raises KeyError with a descriptive error message if version is unknown.
    """
    if version not in POLICIES:
        raise KeyError(
            f"Policy version '{version}' not found. Available versions: {sorted(POLICIES.keys())}"
        )
    return POLICIES[version]
