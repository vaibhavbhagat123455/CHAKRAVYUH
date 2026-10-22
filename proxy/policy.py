"""Security policy configuration and registry for AI Chakravyuh proxy.

AI Chakravyuh Checkpoint Rule Table:

| Rule ID | Condition | Decision |
| :--- | :--- | :--- |
| R1 | Tool not in allowlist | DENY |
| R2 | External destination AND sensitive_data_risk == "high" | DENY |
| R3 | High-impact tool AND (prompt_injection OR goal_drift) | approval_required => HOLD, else DENY |
| R4 | Signals is None AND high-impact tool | HOLD |
| R5 | Approval-required tool | HOLD |
| R6 | summarize_document, safe summary, no injection, no drift, low risk | ALLOW |
| R7 | Anything else (default fallback) | HOLD |
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
from typing import Any, Dict, Optional, Tuple, Union

from core.contracts import POLICY_VERSION

_POLICY_KEYS = frozenset({
    "policy_version", "allowed_tools", "high_impact_tools",
    "approval_required_tools", "safe_domains", "sensitive_categories",
    "destination_argument_keys", "public_file_markers",
})


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
        for field, target in (
            ("allowed_tools", frozenset), ("high_impact_tools", frozenset),
            ("approval_required_tools", frozenset), ("safe_domains", frozenset),
            ("sensitive_categories", frozenset), ("destination_argument_keys", tuple),
            ("public_file_markers", tuple),
        ):
            val = getattr(self, field)
            if not isinstance(val, target):
                object.__setattr__(self, field, target(val))

        if not self.high_impact_tools.issubset(self.allowed_tools):
            raise ValueError(f"high_impact_tools must be subset of allowed_tools: {sorted(self.high_impact_tools - self.allowed_tools)}")
        if not self.approval_required_tools.issubset(self.allowed_tools):
            raise ValueError(f"approval_required_tools must be subset of allowed_tools: {sorted(self.approval_required_tools - self.allowed_tools)}")


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

POLICIES: Dict[str, PolicyConfig] = {POLICY_V1.policy_version: POLICY_V1}


def get_policy(version: str) -> PolicyConfig:
    """Retrieve PolicyConfig by policy_version identifier."""
    if version not in POLICIES:
        raise KeyError(f"Policy version '{version}' not found. Available versions: {sorted(POLICIES.keys())}")
    return POLICIES[version]


def load_policy(path: Union[str, Path]) -> PolicyConfig:
    """Load and validate PolicyConfig from a JSON file."""
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        raise ValueError(f"Failed to read policy JSON file '{path}': {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError(f"Policy JSON must be an object, got {type(data).__name__}")
    if set(data.keys()) - _POLICY_KEYS:
        raise ValueError(f"Unknown keys in policy JSON: {sorted(set(data.keys()) - _POLICY_KEYS)}")
    if _POLICY_KEYS - set(data.keys()):
        raise ValueError(f"Missing required keys in policy JSON: {sorted(_POLICY_KEYS - set(data.keys()))}")

    version = data["policy_version"]
    if not isinstance(version, str) or not version.strip():
        raise ValueError(f"Invalid type for policy_version: expected non-empty str, got {version!r}")

    def _seq(key: str, typ: type) -> Any:
        v = data[key]
        if not isinstance(v, (list, tuple, set, frozenset)) or not all(isinstance(x, str) for x in v):
            raise ValueError(f"Invalid type for {key}: expected sequence of strings")
        return typ(v)

    return PolicyConfig(
        policy_version=version,
        allowed_tools=_seq("allowed_tools", frozenset),
        high_impact_tools=_seq("high_impact_tools", frozenset),
        approval_required_tools=_seq("approval_required_tools", frozenset),
        safe_domains=_seq("safe_domains", frozenset),
        sensitive_categories=_seq("sensitive_categories", frozenset),
        destination_argument_keys=_seq("destination_argument_keys", tuple),
        public_file_markers=_seq("public_file_markers", tuple),
    )


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
    """Determine whether destination targets an external/untrusted domain."""
    if not destination or not destination.strip():
        return False
    dest = destination.strip()
    domain = dest.rsplit("@", 1)[1].strip().lower() if "@" in dest else dest.lower()
    if not domain:
        return False
    return not any(domain == s.lower() or domain.endswith("." + s.lower()) for s in policy.safe_domains)


def is_safe_summary(arguments: Dict[str, Any], policy: PolicyConfig) -> bool:
    """Return True if summarize_document targets a safe public file with no sensitive category."""
    target: Optional[str] = None
    for key in ("file", "filename", "path", "document", "doc", "target"):
        val = arguments.get(key)
        if isinstance(val, str) and val.strip():
            target = val.strip().replace("\\", "/").split("/")[-1].lower()
            break
    if not target or not any(target.startswith(m.lower()) for m in policy.public_file_markers):
        return False

    for cat in policy.sensitive_categories:
        c = cat.lower()
        if c in target or any(isinstance(v, str) and c in v.lower() for v in arguments.values()):
            return False
    return True
