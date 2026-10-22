"""Versioned deterministic policy matrix for the MCP checkpoint and replay."""

from __future__ import annotations

import re
from dataclasses import replace
from typing import Any, Iterator, Mapping

from .canonical import sha256_hex
from .contracts import POLICY_VERSION, canonical_json
from .layers import build_layer_results
from .schemas import Decision, DecisionSignals, ToolRequest

SAFE_TOOLS = frozenset({"summarize_document"})
APPROVAL_TOOLS = frozenset({"send_email", "upload_file", "http_post", "export_records"})
SUPPORTED_POLICY_VERSIONS = frozenset({POLICY_VERSION})

SENSITIVE_TERMS = frozenset(
    {
        "student record",
        "student records",
        "student database",
        "personal data",
        "identity data",
        "confidential report",
        "confidential",
        "password",
        "secret",
        "private records",
    }
)
EXTERNAL_TERMS = frozenset(
    {
        "external",
        "outside the organisation",
        "outside the organization",
        "unknown recipient",
        "public email",
        "public recipient",
    }
)
_URL_RE = re.compile(r"https?://|ftp://", re.IGNORECASE)

_REASONS = {
    "unknown_tool": "The requested tool is not on the approved allowlist.",
    "injection_or_drift_with_sensitive_or_external": (
        "The content attempts to change the authorised task while moving sensitive data "
        "or reaching an external destination."
    ),
    "sensitive_external_transfer_requires_approval": (
        "Sensitive data would leave the organisation and requires exact human approval."
    ),
    "approval_required_tool": "The requested tool requires exact, expiring human approval.",
    "unsafe_content_for_safe_tool": (
        "The content contains unsafe instructions even though the requested tool is low privilege."
    ),
    "sensitive_data_requires_review": (
        "The request touches sensitive data and requires human review before execution."
    ),
    "safe_tool_low_risk": (
        "The requested tool is low privilege and the recorded signals show no high-risk condition."
    ),
    "default_review": "The request does not match a safe rule and is held for review.",
}


def _iter_strings(value: Any) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for key, item in value.items():
            yield str(key)
            yield from _iter_strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _iter_strings(item)


def _request_text(request: ToolRequest) -> str:
    return " ".join(
        _iter_strings(
            {
                "tool": request.tool,
                "purpose": request.purpose,
                "scenario_id": request.scenario_id,
                "arguments": request.arguments,
            }
        )
    ).lower()


def has_sensitive_arguments(request: ToolRequest) -> bool:
    text = _request_text(request)
    return any(term in text for term in SENSITIVE_TERMS)


def is_external_destination(request: ToolRequest) -> bool:
    text = _request_text(request)
    return bool(_URL_RE.search(text)) or any(term in text for term in EXTERNAL_TERMS)


def _tool_class(tool: str) -> str:
    if tool in SAFE_TOOLS:
        return "safe"
    if tool in APPROVAL_TOOLS:
        return "approval"
    return "unknown"


def _evidence_id(
    request: ToolRequest,
    signals: DecisionSignals,
    policy_version: str,
    decision: str,
    matched_rule: str,
) -> str:
    material = {
        "request": request.to_dict(),
        "signals": signals.to_dict(),
        "policy_version": policy_version,
        "decision": decision,
        "matched_rule": matched_rule,
    }
    return "ev-" + sha256_hex(canonical_json(material))[:16]


def evaluate_policy(
    request: ToolRequest,
    signals: DecisionSignals | Mapping[str, Any],
    policy_version: str = POLICY_VERSION,
) -> Decision:
    """Return one deterministic ALLOW, HOLD or DENY decision.

    The AI recommendation is recorded as evidence but never becomes the decision.
    """
    if policy_version not in SUPPORTED_POLICY_VERSIONS:
        raise ValueError(
            f"unknown policy_version {policy_version!r}; supported: {sorted(SUPPORTED_POLICY_VERSIONS)}"
        )
    if isinstance(signals, Mapping):
        signals = DecisionSignals.from_mapping(signals)
    if not isinstance(signals, DecisionSignals):
        raise TypeError("signals must be DecisionSignals or a mapping")

    tool = request.tool
    tool_class = _tool_class(tool)
    injection_or_drift = signals.prompt_injection or signals.goal_drift
    sensitive = signals.sensitive_data_risk == "high" or has_sensitive_arguments(request)
    external = is_external_destination(request)

    if tool_class == "unknown":
        decision = "DENY"
        matched_rule = "unknown_tool"
    elif injection_or_drift and (sensitive or external):
        decision = "DENY"
        matched_rule = "injection_or_drift_with_sensitive_or_external"
    elif sensitive and external:
        decision = "HOLD"
        matched_rule = "sensitive_external_transfer_requires_approval"
    elif tool_class == "approval":
        decision = "HOLD"
        matched_rule = "approval_required_tool"
    elif injection_or_drift:
        decision = "HOLD"
        matched_rule = "unsafe_content_for_safe_tool"
    elif sensitive:
        decision = "HOLD"
        matched_rule = "sensitive_data_requires_review"
    else:
        decision = "ALLOW"
        matched_rule = "safe_tool_low_risk"

    policy_facts = {
        "matched_rule": matched_rule,
        "tool": tool,
        "tool_class": tool_class,
        "prompt_injection": signals.prompt_injection,
        "goal_drift": signals.goal_drift,
        "sensitive_data": sensitive,
        "external_destination": external,
        "sensitive_data_risk": signals.sensitive_data_risk,
        "risk_score": float(signals.risk_score),
        "ai_recommended_action": signals.recommended_action,
    }
    evidence_id = _evidence_id(request, signals, policy_version, decision, matched_rule)
    provisional = Decision(
        request_id=request.request_id,
        decision=decision,
        evidence_id=evidence_id,
        reason=_REASONS[matched_rule],
        policy_version=policy_version,
        signals=signals,
        policy_facts=policy_facts,
    )
    return replace(
        provisional,
        layer_results=build_layer_results(request, signals, provisional),
    )


__all__ = [
    "APPROVAL_TOOLS",
    "EXTERNAL_TERMS",
    "SAFE_TOOLS",
    "SENSITIVE_TERMS",
    "SUPPORTED_POLICY_VERSIONS",
    "evaluate_policy",
    "has_sensitive_arguments",
    "is_external_destination",
]
