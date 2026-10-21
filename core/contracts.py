"""Frozen cross-module conventions."""

import json
from typing import Any, Dict

DECISIONS = frozenset({"ALLOW", "HOLD", "DENY"})
POLICY_VERSION = "v1"
LOG_EVENT_TYPES = frozenset({
    "REQUEST_RECEIVED", "AI_ANALYSIS", "LAYER_EVALUATED",
    "CHECKPOINT_DECISION", "APPROVAL_CREATED", "APPROVAL_ATTEMPT",
    "TOOL_STARTED", "TOOL_COMPLETED", "TOOL_BLOCKED", "CONTAINMENT",
})


def canonical_json(value: Dict[str, Any]) -> str:
    """The one JSON representation used for hashes and fingerprints."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def validate_decision(value: str) -> str:
    if value not in DECISIONS:
        raise ValueError(f"decision must be one of {sorted(DECISIONS)}")
    return value


def validate_event_type(value: str) -> str:
    if value not in LOG_EVENT_TYPES:
        raise ValueError(f"unknown event_type: {value}")
    return value
