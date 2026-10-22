"""Deterministic security checkpoint for AI Chakravyuh proxy."""

from __future__ import annotations

from typing import Optional

from proxy.canonical import canonical_json, sha256_hex
from proxy.models import DecisionSignals, ToolRequest


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
