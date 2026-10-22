"""Frozen cross-module conventions."""

import json
from typing import Any

DECISIONS = frozenset({"ALLOW", "HOLD", "DENY"})
POLICY_VERSION = "v1"
LOG_EVENT_TYPES = frozenset({
    "SCENARIO_START",
    "REQUEST_RECEIVED",
    "AI_ANALYSIS",
    "LAYER_EVALUATED",
    "CHECKPOINT_DECISION",
    "APPROVAL_CREATED",
    "APPROVAL_SENT",
    "APPROVAL_ATTEMPT",
    "APPROVAL_VERIFIED",
    "APPROVAL_REJECTED",
    "APPROVAL_EXPIRED",
    "TOOL_STARTED",
    "TOOL_COMPLETED",
    "TOOL_BLOCKED",
    "TOOL_TIMEOUT",
    "CONTAINMENT",
    "SCENARIO_END",
})


def canonical_json(value: Any) -> str:
    """The one JSON representation used for hashes and fingerprints."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def validate_decision(value: str) -> str:
    if value not in DECISIONS:
        raise ValueError(f"decision must be one of {sorted(DECISIONS)}")
    return value


def validate_event_type(value: str) -> str:
    if value not in LOG_EVENT_TYPES:
        raise ValueError(f"unknown event_type: {value}")
    return value
