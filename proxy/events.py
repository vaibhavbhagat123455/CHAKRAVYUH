"""Mapping and emission of proxy logical events to core event types."""

from __future__ import annotations

from typing import Any, Dict, Mapping, NamedTuple, Optional

from core.contracts import validate_event_type

# Logical event names used by proxy
REQUEST_RECEIVED = "REQUEST_RECEIVED"
ANALYSIS_RECORDED = "ANALYSIS_RECORDED"
LAYER_EVALUATED = "LAYER_EVALUATED"
CHECKPOINT_DECISION = "CHECKPOINT_DECISION"
TOOL_STARTED = "TOOL_STARTED"
TOOL_COMPLETED = "TOOL_COMPLETED"
TOOL_BLOCKED = "TOOL_BLOCKED"
TOOL_TIMEOUT = "TOOL_TIMEOUT"
HOLD_CREATED = "HOLD_CREATED"
HOLD_RELEASED = "HOLD_RELEASED"
HOLD_DENIED = "HOLD_DENIED"
HOLD_EXPIRED = "HOLD_EXPIRED"

LOGICAL_EVENT_NAMES = frozenset({
    REQUEST_RECEIVED,
    ANALYSIS_RECORDED,
    LAYER_EVALUATED,
    CHECKPOINT_DECISION,
    TOOL_STARTED,
    TOOL_COMPLETED,
    TOOL_BLOCKED,
    TOOL_TIMEOUT,
    HOLD_CREATED,
    HOLD_RELEASED,
    HOLD_DENIED,
    HOLD_EXPIRED,
})


class _EventMapping(NamedTuple):
    core_type: str
    outcome: Optional[str] = None


EVENT_MAPPING: Mapping[str, _EventMapping] = {
    REQUEST_RECEIVED: _EventMapping("REQUEST_RECEIVED"),
    ANALYSIS_RECORDED: _EventMapping("AI_ANALYSIS"),
    LAYER_EVALUATED: _EventMapping("LAYER_EVALUATED"),
    CHECKPOINT_DECISION: _EventMapping("CHECKPOINT_DECISION"),
    TOOL_STARTED: _EventMapping("TOOL_STARTED"),
    TOOL_COMPLETED: _EventMapping("TOOL_COMPLETED"),
    TOOL_BLOCKED: _EventMapping("TOOL_BLOCKED"),
    TOOL_TIMEOUT: _EventMapping("CONTAINMENT"),
    HOLD_CREATED: _EventMapping("APPROVAL_CREATED"),
    HOLD_RELEASED: _EventMapping("APPROVAL_ATTEMPT", outcome="released"),
    HOLD_DENIED: _EventMapping("APPROVAL_ATTEMPT", outcome="denied"),
    HOLD_EXPIRED: _EventMapping("APPROVAL_ATTEMPT", outcome="expired"),
}


def map_logical_event(logical_event: str) -> tuple[str, Optional[str]]:
    """Map logical proxy event to core event type and optional outcome.

    Raises ValueError for unknown logical event names.
    """
    if logical_event not in EVENT_MAPPING:
        raise ValueError(f"Unknown logical event name: {logical_event!r}")
    mapping = EVENT_MAPPING[logical_event]
    return mapping.core_type, mapping.outcome


def emit(
    log: Any,
    logical_event: str,
    request_id: str,
    payload: Dict[str, Any],
) -> Dict[str, Any]:
    """Format, validate, and emit a logical event through the log sink.

    Puts request_id and subtype=logical_event into payload. If applicable,
    sets payload["outcome"]. Validates the core event type and calls
    log.append_event(core_type, enriched_payload).
    """
    if not isinstance(request_id, str) or not request_id.strip():
        raise ValueError(f"request_id must be a non-empty string, got: {request_id!r}")

    core_type, outcome = map_logical_event(logical_event)

    # Validate mapped core event type
    validate_event_type(core_type)

    enriched_payload = dict(payload)
    enriched_payload["request_id"] = request_id
    enriched_payload["subtype"] = logical_event
    if outcome is not None:
        enriched_payload["outcome"] = outcome

    return log.append_event(core_type, enriched_payload)
