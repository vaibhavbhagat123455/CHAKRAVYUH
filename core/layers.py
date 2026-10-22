"""Reference implementation of the seven evidence layers."""

from __future__ import annotations

from .canonical import sha256_hex
from .contracts import canonical_json
from .schemas import Decision, DecisionSignals, LayerResult, ToolRequest


def _layer_evidence_id(request_id: str, layer_id: str, status: str, decision: str) -> str:
    material = {
        "request_id": request_id,
        "layer_id": layer_id,
        "status": status,
        "decision": decision,
    }
    return "ev-" + sha256_hex(canonical_json(material))[:16]


def _result(
    request: ToolRequest,
    decision: Decision,
    layer_id: str,
    status: str,
    reason: str,
) -> LayerResult:
    return LayerResult(
        layer_id=layer_id,
        status=status,
        reason=reason,
        evidence_id=_layer_evidence_id(request.request_id, layer_id, status, decision.decision),
    )


def build_layer_results(
    request: ToolRequest,
    signals: DecisionSignals,
    decision: Decision,
) -> tuple[LayerResult, ...]:
    """Return deterministic evidence for DWAAR through DRISHTI."""
    tool_class = decision.policy_facts.get("tool_class", "unknown")
    external = bool(decision.policy_facts.get("external_destination", False))
    sensitive = bool(decision.policy_facts.get("sensitive_data", False))

    dwaar_status = "BLOCK" if signals.prompt_injection else "PASS"
    dwaar_reason = (
        "untrusted content contains instruction-override patterns"
        if signals.prompt_injection
        else "no instruction-override pattern detected in untrusted content"
    )

    pehchaan_status = "PASS"
    pehchaan_reason = "request identity, purpose and scenario scope are present"

    smriti_status = "PASS" if request.scenario_id else "REVIEW"
    smriti_reason = (
        "request is bound to a repeatable synthetic scenario"
        if request.scenario_id
        else "request has no scenario provenance"
    )

    sankalp_status = "BLOCK" if signals.goal_drift else "PASS"
    sankalp_reason = (
        "proposed action is outside the authorised goal"
        if signals.goal_drift
        else "proposed action is aligned with the authorised goal"
    )

    if tool_class == "unknown":
        astra_status = "BLOCK"
        astra_reason = "tool is not on the safe or approval-required allowlist"
    elif tool_class == "approval":
        astra_status = "REVIEW"
        astra_reason = "tool is restricted and requires approval or denial"
    else:
        astra_status = "PASS"
        astra_reason = "tool is on the least-privilege allowlist"

    if decision.decision == "HOLD":
        maryada_status = "REVIEW"
        maryada_reason = "request is held for exact, expiring human approval"
    else:
        maryada_status = "PASS"
        maryada_reason = "no approval gate is required for this decision"

    if sensitive and external:
        drishti_reason = "sensitive data movement to an external destination is contained"
    elif sensitive:
        drishti_reason = "sensitive data is contained within the review path"
    else:
        drishti_reason = "event is recorded in the hash-chained security log"

    return (
        _result(request, decision, "DWAAR", dwaar_status, dwaar_reason),
        _result(request, decision, "PEHCHAAN", pehchaan_status, pehchaan_reason),
        _result(request, decision, "SMRITI", smriti_status, smriti_reason),
        _result(request, decision, "SANKALP", sankalp_status, sankalp_reason),
        _result(request, decision, "ASTRA", astra_status, astra_reason),
        _result(request, decision, "MARYADA", maryada_status, maryada_reason),
        _result(request, decision, "DRISHTI", "PASS", drishti_reason),
    )


__all__ = ["build_layer_results"]
