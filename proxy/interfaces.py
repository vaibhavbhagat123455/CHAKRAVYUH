"""Typing protocols for external dependencies and mockable interfaces."""

from __future__ import annotations

from typing import Any, Dict, Protocol, runtime_checkable

from proxy.models import ApprovalResult, ToolRequest


@runtime_checkable
class LogWriter(Protocol):
    """Protocol for append-only log engine."""

    def append_event(self, event_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Append an event to the security audit trail and return the stored envelope."""
        ...


@runtime_checkable
class Analyser(Protocol):
    """Protocol for AI threat and intent analyser."""

    def analyse_tool_call(self, tool_call: Dict[str, Any], original_goal: str) -> Dict[str, Any]:
        """Analyse tool call for prompt injection, goal drift, and sensitive data risk."""
        ...


@runtime_checkable
class ApprovalService(Protocol):
    """Protocol for human out-of-band approval management."""

    def create_approval(self, request: ToolRequest) -> Dict[str, Any]:
        """Register a pending approval bound to the given ToolRequest."""
        ...

    def verify_approval(self, code: str, request: ToolRequest) -> ApprovalResult:
        """Verify an approval code against the bound ToolRequest action."""
        ...


@runtime_checkable
class ToolExecutor(Protocol):
    """Protocol for injected tool execution engine."""

    def execute(self, tool: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a simulated tool with validated arguments."""
        ...


@runtime_checkable
class Clock(Protocol):
    """Protocol for time provider used in expiry calculations."""

    def now(self) -> float:
        """Return current timestamp as seconds since epoch."""
        ...
