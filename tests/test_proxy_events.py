"""Tests for proxy events mapping and emission."""

import unittest
from typing import Any, Dict

from core.contracts import validate_event_type
from proxy.events import (
    ANALYSIS_RECORDED,
    HOLD_CREATED,
    HOLD_DENIED,
    HOLD_EXPIRED,
    HOLD_RELEASED,
    LOGICAL_EVENT_NAMES,
    REQUEST_RECEIVED,
    TOOL_TIMEOUT,
    emit,
    map_logical_event,
)


class DummyLog:
    """Minimal dummy log sink recording calls to append_event."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, Dict[str, Any]]] = []

    def append_event(self, event_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        self.calls.append((event_type, payload))
        return {
            "sequence": len(self.calls),
            "event_id": f"evt-{len(self.calls)}",
            "event_type": event_type,
            "request_id": payload.get("request_id"),
            "payload": payload,
        }


class TestProxyEvents(unittest.TestCase):
    """Verify logical to core event mapping and emission behavior."""

    def test_all_logical_events_map_to_valid_core_types(self) -> None:
        for logical_name in LOGICAL_EVENT_NAMES:
            core_type, outcome = map_logical_event(logical_name)
            # validate_event_type will raise ValueError if invalid
            validated = validate_event_type(core_type)
            self.assertEqual(validated, core_type)

            # Check outcome for HOLD lifecycle
            if logical_name == HOLD_RELEASED:
                self.assertEqual(outcome, "released")
            elif logical_name == HOLD_DENIED:
                self.assertEqual(outcome, "denied")
            elif logical_name == HOLD_EXPIRED:
                self.assertEqual(outcome, "expired")
            elif logical_name == HOLD_CREATED:
                self.assertEqual(core_type, "APPROVAL_CREATED")
                self.assertIsNone(outcome)

    def test_special_mappings(self) -> None:
        self.assertEqual(map_logical_event(ANALYSIS_RECORDED), ("AI_ANALYSIS", None))
        self.assertEqual(map_logical_event(TOOL_TIMEOUT), ("CONTAINMENT", None))

    def test_unknown_logical_event_raises_value_error(self) -> None:
        with self.assertRaises(ValueError):
            map_logical_event("NON_EXISTENT_EVENT")

    def test_emit_formats_payload_and_calls_log(self) -> None:
        log = DummyLog()
        envelope = emit(
            log=log,
            logical_event=HOLD_RELEASED,
            request_id="req-501",
            payload={"action": "test_action"},
        )
        self.assertEqual(len(log.calls), 1)
        core_type, payload = log.calls[0]
        self.assertEqual(core_type, "APPROVAL_ATTEMPT")
        self.assertEqual(payload["request_id"], "req-501")
        self.assertEqual(payload["subtype"], HOLD_RELEASED)
        self.assertEqual(payload["outcome"], "released")
        self.assertEqual(payload["action"], "test_action")
        self.assertEqual(envelope["event_type"], "APPROVAL_ATTEMPT")

    def test_emit_invalid_request_id_raises_value_error(self) -> None:
        log = DummyLog()
        with self.assertRaises(ValueError):
            emit(log, REQUEST_RECEIVED, "", {"key": "val"})


if __name__ == "__main__":
    unittest.main()
