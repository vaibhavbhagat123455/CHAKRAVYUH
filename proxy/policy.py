"""Security policy configuration and registry for AI Chakravyuh proxy."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

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


def is_allowed_tool(tool: str, policy: PolicyConfig) -> bool:
    """Return True if tool is explicitly present in policy.allowed_tools."""
    return bool(tool and tool in policy.allowed_tools)


def is_high_impact(tool: str, policy: PolicyConfig) -> bool:
    """Return True if tool is designated as high impact in policy.high_impact_tools."""
    return bool(tool and tool in policy.high_impact_tools)


def requires_approval(tool: str, policy: PolicyConfig) -> bool:
    """Return True if tool requires human approval in policy.approval_required_tools."""
    return bool(tool and tool in policy.approval_required_tools)


def destination_of(arguments: Dict[str, Any], policy: PolicyConfig) -> Optional[str]:
    """Extract destination argument based on ordered policy.destination_argument_keys."""
    for key in policy.destination_argument_keys:
        val = arguments.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return None


def is_external_destination(destination: Optional[str], policy: PolicyConfig) -> bool:
    """Determine whether destination targets an external/untrusted domain.

    Edge cases:
    - Missing destination (None or empty/whitespace) is NOT external (returns False).
    - Destinations without '@' are evaluated directly against safe domains.
    - Uppercase domains are normalized.
    - Subdomain tricks like 'example.edu.evil.com' are recognized as external.
    - Subdomains of safe domains (e.g. 'cs.example.edu') are recognized as internal.
    """
    if not destination or not destination.strip():
        return False

    dest = destination.strip()
    if "@" in dest:
        domain = dest.rsplit("@", 1)[1].strip().lower()
    else:
        domain = dest.lower()

    if not domain:
        return False

    is_safe = any(
        domain == safe.lower() or domain.endswith("." + safe.lower())
        for safe in policy.safe_domains
    )
    return not is_safe


def is_safe_summary(arguments: Dict[str, Any], policy: PolicyConfig) -> bool:
    """Return True if summarize_document targets a safe public file with no sensitive category."""
    target: Optional[str] = None
    for key in ("file", "filename", "path", "document", "doc", "target"):
        val = arguments.get(key)
        if isinstance(val, str) and val.strip():
            target = val.strip().replace("\\", "/").split("/")[-1].lower()
            break

    if not target:
        return False

    has_public_marker = any(target.startswith(m.lower()) for m in policy.public_file_markers)
    if not has_public_marker:
        return False

    for cat in policy.sensitive_categories:
        cat_lower = cat.lower()
        if cat_lower in target:
            return False
        for val in arguments.values():
            if isinstance(val, str) and cat_lower in val.lower():
                return False

    return True
