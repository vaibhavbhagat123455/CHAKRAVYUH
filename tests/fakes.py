"""Test doubles and in-memory fakes for proxy unit and integration tests."""

from __future__ import annotations

import time
from typing import Any, Callable, Dict, List, Optional

from core.contracts import validate_event_type
from proxy.canonical import action_digest
from proxy.interfaces import (
    Analyser,
    ApprovalService,
    Clock,
    LogWriter,
    ToolExecutor,
)
from proxy.models import ApprovalResult, ToolRequest


class FakeLog(LogWriter):
    """In-memory log engine fake validating event types and payload contracts."""

    def __init__(self) -> None:
        self.events: List[Dict[str, Any]] = []
        self._sequence: int = 1

    def append_event(self, event_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and append an event envelope to memory."""
        validate_event_type(event_type)

        if not isinstance(payload, dict):
            raise ValueError(f"payload must be a dict, got: {type(payload).__name__}")

        request_id = payload.get("request_id")
        if not request_id or not isinstance(request_id, str) or not request_id.strip():
            raise ValueError(f"Payload missing valid request_id: {request_id!r}")

        envelope: Dict[str, Any] = {
            "sequence": self._sequence,
            "event_id": f"evt-{self._sequence:03d}",
            "event_type": event_type,
            "request_id": request_id,
            "payload": dict(payload),
        }
        self.events.append(envelope)
        self._sequence += 1
        return envelope

    def get_events_for_request(self, request_id: str) -> List[Dict[str, Any]]:
        """Filter events by request_id."""
        return [e for e in self.events if e.get("request_id") == request_id]


class FakeAnalyser(Analyser):
    """Configurable AI threat analyser double."""

    def __init__(
        self,
        default_result: Optional[Dict[str, Any]] = None,
        exception_to_raise: Optional[Exception] = None,
    ) -> None:
        self.calls: List[Dict[str, Any]] = []
        self.result: Dict[str, Any] = default_result or {
            "prompt_injection": False,
            "goal_drift": False,
            "sensitive_data_risk": "low",
            "risk_score": 0.05,
            "recommended_action": "ALLOW",
            "reason": "Synthetic benign tool call",
        }
        self.exception_to_raise: Optional[Exception] = exception_to_raise

    def analyse_tool_call(self, tool_call: Dict[str, Any], original_goal: str) -> Dict[str, Any]:
        """Record analysis call and return preset result or raise exception."""
        self.calls.append({"tool_call": tool_call, "original_goal": original_goal})
        if self.exception_to_raise is not None:
            raise self.exception_to_raise
        return dict(self.result)


class SpyExecutor(ToolExecutor):
    """Spy executor that counts calls, records arguments, and simulates delays/errors."""

    def __init__(
        self,
        default_result: Optional[Dict[str, Any]] = None,
        delay_seconds: float = 0.0,
    ) -> None:
        self.calls: List[Dict[str, Any]] = []
        self.default_result: Dict[str, Any] = default_result or {"status": "success", "simulated": True}
        self.delay_seconds: float = delay_seconds
        self.exception_to_raise: Optional[Exception] = None

    @property
    def call_count(self) -> int:
        return len(self.calls)

    def execute(
        self,
        tool: str,
        arguments: Dict[str, Any],
        auth_token: Optional[Any] = None,
        request_id: Optional[str] = None,
        **kwargs: Any,
    ) -> Dict[str, Any]:
        """Record call, apply optional delay, and return configured result."""
        self.calls.append({"tool": tool, "arguments": arguments, "auth_token": auth_token, "request_id": request_id})
        if self.delay_seconds > 0:
            time.sleep(self.delay_seconds)
        if self.exception_to_raise is not None:
            raise self.exception_to_raise
        return dict(self.default_result)


class FakeApprovalService(ApprovalService):
    """Configurable approval service double for human verification flows."""

    def __init__(self, auto_approve: bool = True) -> None:
        self.created: List[ToolRequest] = []
        self.verified: List[tuple[str, ToolRequest]] = []
        self.auto_approve: bool = auto_approve
        self.configured_result: Optional[ApprovalResult] = None

    def create_approval(self, request: ToolRequest) -> Dict[str, Any]:
        """Record creation and return approval descriptor."""
        self.created.append(request)
        digest = action_digest(request.tool, request.arguments)
        return {
            "approval_id": f"appr-{request.request_id}",
            "action_digest": digest,
            "request_id": request.request_id,
        }

    def verify_approval(self, code: str, request: ToolRequest) -> ApprovalResult:
        """Record verification attempt and return ApprovalResult."""
        self.verified.append((code, request))
        if self.configured_result is not None:
            return self.configured_result
        digest = action_digest(request.tool, request.arguments)
        return ApprovalResult(
            approved=self.auto_approve,
            approval_id=f"appr-{request.request_id}",
            action_digest=digest,
            reason="Approved by fake service" if self.auto_approve else "Rejected by fake service",
        )


class FakeClock(Clock):
    """Controllable clock double for testing time-dependent behavior."""

    def __init__(self, start_time: float = 1000.0) -> None:
        self._current_time: float = start_time

    def now(self) -> float:
        """Return preset time."""
        return self._current_time

    def set_time(self, new_time: float) -> None:
        """Explicitly set current timestamp."""
        self._current_time = new_time

    def advance(self, seconds: float) -> None:
        """Advance current time forward by specified seconds."""
        self._current_time += seconds
