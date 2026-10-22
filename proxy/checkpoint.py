"""Deterministic security checkpoint for AI Chakravyuh proxy."""

from __future__ import annotations

from typing import Optional

from core.contracts import POLICY_VERSION
from proxy.canonical import canonical_json, sha256_hex
from proxy.models import DENY, HOLD, Decision, DecisionSignals, ToolRequest
from proxy.policy import (
    PolicyConfig,
    destination_of,
    get_policy,
    is_allowed_tool,
    is_external_destination,
    is_high_impact,
    requires_approval,
)

# Rule identifiers
RULE_R1 = "R1"
RULE_R2 = "R2"
RULE_R3 = "R3"
RULE_R4 = "R4"
RULE_R5 = "R5"
RULE_R6 = "R6"
RULE_R7 = "R7"

# Standard reason templates (never embed raw argument values or secrets)
REASON_R1_UNALLOWED_TOOL = "Tool is not in allowed policy allowlist"
REASON_R2_EXTERNAL_SENSITIVE = "External destination with high sensitive data risk"
REASON_R3_HIGH_IMPACT_THREAT_HOLD = "High-impact tool under threat requires human approval hold"
REASON_R3_HIGH_IMPACT_THREAT_DENY = "High-impact tool under threat denied by policy"
REASON_R4_MISSING_SIGNALS_HOLD = "High-impact tool without AI threat analysis signals placed on hold"
REASON_R5_APPROVAL_REQUIRED_HOLD = "High-impact tool requires explicit human authorization"
REASON_R6_SAFE_SUMMARY_ALLOW = "Safe document summary permitted under policy allowlist"
REASON_R7_DEFAULT_HOLD = "Tool call did not match allowlist rule; placed on defensive hold"


def make_evidence_id(
    request: ToolRequest,
    signals: Optional[DecisionSignals],
    policy_version: str,
) -> str:
    """Generate deterministic evidence identifier.

    ev-<first 12 hex of sha256(canonical(request) + canonical(signals or None) + policy_version)>.
    """
    req_json = canonical_json(request.to_dict())
    sig_data = signals.to_dict() if signals is not None else None
    sig_json = canonical_json(sig_data)
    combined = req_json + sig_json + policy_version
    digest = sha256_hex(combined)
    return f"ev-{digest[:12]}"


def decide(
    request: ToolRequest,
    signals: Optional[DecisionSignals],
    policy_version: str = POLICY_VERSION,
    policy: Optional[PolicyConfig] = None,
) -> Decision:
    """Evaluate pure, deterministic checkpoint decision over request and signals.

    Pure and deterministic: no current time, randomness, network, LLM or file I/O.
    Resolves policy from get_policy(policy_version) when policy is None.
    First match wins across rules R1 through R7.
    """
    if policy is None:
        policy = get_policy(policy_version)

    evidence_id = make_evidence_id(request, signals, policy_version)
    sig_dict = signals.to_dict() if signals is not None else None

    # R1: Tool not allowed => DENY
    if not is_allowed_tool(request.tool, policy):
        return Decision(
            request_id=request.request_id,
            decision=DENY,
            evidence_id=evidence_id,
            reason=REASON_R1_UNALLOWED_TOOL,
            policy_version=policy_version,
            risk_signals=sig_dict,
            rule_id=RULE_R1,
        )

    # R2: External destination AND sensitive_data_risk == "high" => DENY
    dest = destination_of(request.arguments, policy)
    if is_external_destination(dest, policy) and signals is not None and signals.sensitive_data_risk == "high":
        return Decision(
            request_id=request.request_id,
            decision=DENY,
            evidence_id=evidence_id,
            reason=REASON_R2_EXTERNAL_SENSITIVE,
            policy_version=policy_version,
            risk_signals=sig_dict,
            rule_id=RULE_R2,
        )

    # R3: High-impact tool AND (prompt_injection OR goal_drift)
    if is_high_impact(request.tool, policy) and signals is not None:
        if signals.prompt_injection or signals.goal_drift:
            if requires_approval(request.tool, policy):
                return Decision(
                    request_id=request.request_id,
                    decision=HOLD,
                    evidence_id=evidence_id,
                    reason=REASON_R3_HIGH_IMPACT_THREAT_HOLD,
                    policy_version=policy_version,
                    risk_signals=sig_dict,
                    rule_id=RULE_R3,
                )
            return Decision(
                request_id=request.request_id,
                decision=DENY,
                evidence_id=evidence_id,
                reason=REASON_R3_HIGH_IMPACT_THREAT_DENY,
                policy_version=policy_version,
                risk_signals=sig_dict,
                rule_id=RULE_R3,
            )

    # R4: signals is None AND high-impact tool => HOLD
    if signals is None and is_high_impact(request.tool, policy):
        return Decision(
            request_id=request.request_id,
            decision=HOLD,
            evidence_id=evidence_id,
            reason=REASON_R4_MISSING_SIGNALS_HOLD,
            policy_version=policy_version,
            risk_signals=sig_dict,
            rule_id=RULE_R4,
        )

    # R7: Default fallback => HOLD
    return Decision(
        request_id=request.request_id,
        decision=HOLD,
        evidence_id=evidence_id,
        reason=REASON_R7_DEFAULT_HOLD,
        policy_version=policy_version,
        risk_signals=sig_dict,
        rule_id=RULE_R7,
    )
