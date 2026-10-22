"""Deterministic security checkpoint and layer evaluation for AI Chakravyuh proxy."""

from __future__ import annotations

from typing import List, Optional

from core.contracts import POLICY_VERSION
from proxy.canonical import canonical_json, sha256_hex
from proxy.models import (
    ALLOW,
    BLOCK,
    DENY,
    FLAG,
    HOLD,
    PASS,
    Decision,
    DecisionSignals,
    LayerResult,
    ToolRequest,
)
from proxy.policy import (
    PolicyConfig,
    destination_of,
    get_policy,
    is_allowed_tool,
    is_external_destination,
    is_high_impact,
    is_safe_summary,
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

# Layer identifiers and order
LAYER_DWAAR = "DWAAR"
LAYER_PEHCHAAN = "PEHCHAAN"
LAYER_SMRITI = "SMRITI"
LAYER_SANKALP = "SANKALP"
LAYER_ASTRA = "ASTRA"
LAYER_MARYADA = "MARYADA"
LAYER_DRISHTI = "DRISHTI"

LAYER_IDS = (
    LAYER_DWAAR,
    LAYER_PEHCHAAN,
    LAYER_SMRITI,
    LAYER_SANKALP,
    LAYER_ASTRA,
    LAYER_MARYADA,
    LAYER_DRISHTI,
)

# Reason templates (never embed raw argument values or secrets)
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
    """Generate deterministic evidence identifier."""
    req_json = canonical_json(request.to_dict())
    sig_data = signals.to_dict() if signals is not None else None
    combined = req_json + canonical_json(sig_data) + policy_version
    return f"ev-{sha256_hex(combined)[:12]}"


def decide(
    request: ToolRequest,
    signals: Optional[DecisionSignals],
    policy_version: str = POLICY_VERSION,
    policy: Optional[PolicyConfig] = None,
) -> Decision:
    """Evaluate pure, deterministic checkpoint decision over request and signals."""
    if policy is None:
        policy = get_policy(policy_version)

    evidence_id = make_evidence_id(request, signals, policy_version)
    sig_dict = signals.to_dict() if signals is not None else None

    # R1: Tool not allowed => DENY
    if not is_allowed_tool(request.tool, policy):
        return Decision(request.request_id, DENY, evidence_id, REASON_R1_UNALLOWED_TOOL, policy_version, sig_dict, RULE_R1)

    # R2: External destination AND sensitive_data_risk == "high" => DENY
    dest = destination_of(request.arguments, policy)
    if is_external_destination(dest, policy) and signals is not None and signals.sensitive_data_risk == "high":
        return Decision(request.request_id, DENY, evidence_id, REASON_R2_EXTERNAL_SENSITIVE, policy_version, sig_dict, RULE_R2)

    # R3: High-impact tool AND (prompt_injection OR goal_drift)
    if is_high_impact(request.tool, policy) and signals is not None:
        if signals.prompt_injection or signals.goal_drift:
            if requires_approval(request.tool, policy):
                return Decision(request.request_id, HOLD, evidence_id, REASON_R3_HIGH_IMPACT_THREAT_HOLD, policy_version, sig_dict, RULE_R3)
            return Decision(request.request_id, DENY, evidence_id, REASON_R3_HIGH_IMPACT_THREAT_DENY, policy_version, sig_dict, RULE_R3)

    # R4: signals is None AND high-impact tool => HOLD
    if signals is None and is_high_impact(request.tool, policy):
        return Decision(request.request_id, HOLD, evidence_id, REASON_R4_MISSING_SIGNALS_HOLD, policy_version, sig_dict, RULE_R4)

    # R5: approval-required tool => HOLD
    if requires_approval(request.tool, policy):
        return Decision(request.request_id, HOLD, evidence_id, REASON_R5_APPROVAL_REQUIRED_HOLD, policy_version, sig_dict, RULE_R5)

    # R6: safe summary AND no injection AND no drift AND risk "low" => ALLOW
    if (
        is_safe_summary(request.arguments, policy)
        and not is_high_impact(request.tool, policy)
        and signals is not None
        and not signals.prompt_injection
        and not signals.goal_drift
        and signals.sensitive_data_risk == "low"
    ):
        return Decision(request.request_id, ALLOW, evidence_id, REASON_R6_SAFE_SUMMARY_ALLOW, policy_version, sig_dict, RULE_R6)

    # R7: default fallback => HOLD
    return Decision(request.request_id, HOLD, evidence_id, REASON_R7_DEFAULT_HOLD, policy_version, sig_dict, RULE_R7)


def layers(
    request: ToolRequest,
    signals: Optional[DecisionSignals],
    decision: Decision,
    policy: PolicyConfig,
) -> List[LayerResult]:
    """Compute the seven Chakravyuh defense layer evaluation results."""
    ev_id = decision.evidence_id
    results: List[LayerResult] = []

    # 1. DWAAR
    if not is_allowed_tool(request.tool, policy):
        results.append(LayerResult(LAYER_DWAAR, BLOCK, REASON_R1_UNALLOWED_TOOL, ev_id))
    else:
        results.append(LayerResult(LAYER_DWAAR, PASS, "Tool permitted by gateway allowlist", ev_id))

    # 2. PEHCHAAN
    if requires_approval(request.tool, policy):
        results.append(LayerResult(LAYER_PEHCHAAN, FLAG, REASON_R5_APPROVAL_REQUIRED_HOLD, ev_id))
    else:
        results.append(LayerResult(LAYER_PEHCHAAN, PASS, "Caller identity and permissions verified", ev_id))

    # 3. SMRITI
    if signals is None:
        results.append(LayerResult(LAYER_SMRITI, FLAG, REASON_R4_MISSING_SIGNALS_HOLD, ev_id))
    else:
        results.append(LayerResult(LAYER_SMRITI, PASS, "Threat intelligence context available", ev_id))

    # 4. SANKALP
    if signals is not None and signals.goal_drift:
        st = BLOCK if decision.decision == DENY else FLAG
        results.append(LayerResult(LAYER_SANKALP, st, "Goal drift detected against stated purpose", ev_id))
    else:
        results.append(LayerResult(LAYER_SANKALP, PASS, "Intent aligned with declared purpose", ev_id))

    # 5. ASTRA
    if is_high_impact(request.tool, policy):
        st = BLOCK if (decision.decision == DENY and decision.rule_id == RULE_R3) else (FLAG if decision.decision == HOLD else PASS)
        results.append(LayerResult(LAYER_ASTRA, st, "High-impact tool execution monitored", ev_id))
    else:
        results.append(LayerResult(LAYER_ASTRA, PASS, "Standard impact tool execution", ev_id))

    # 6. MARYADA
    dest = destination_of(request.arguments, policy)
    is_ext = is_external_destination(dest, policy)
    if is_ext and signals is not None and signals.sensitive_data_risk == "high":
        results.append(LayerResult(LAYER_MARYADA, BLOCK, REASON_R2_EXTERNAL_SENSITIVE, ev_id))
    elif is_ext or (signals is not None and signals.sensitive_data_risk != "low"):
        st = FLAG if decision.decision == HOLD else PASS
        results.append(LayerResult(LAYER_MARYADA, st, "Destination boundary or data sensitivity flagged", ev_id))
    else:
        results.append(LayerResult(LAYER_MARYADA, PASS, "Within safe operational boundary", ev_id))

    # 7. DRISHTI
    if signals is not None and signals.prompt_injection:
        st = BLOCK if decision.decision == DENY else FLAG
        results.append(LayerResult(LAYER_DRISHTI, st, "Prompt injection attempt detected", ev_id))
    else:
        results.append(LayerResult(LAYER_DRISHTI, PASS, "No anomalous threats observed", ev_id))

    return results
