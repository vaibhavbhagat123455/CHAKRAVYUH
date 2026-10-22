"""Adapter wrappers converting raw callables into strongly-typed proxy interfaces."""

from __future__ import annotations

from typing import Any, Callable, Dict

from core.contracts import validate_event_type
from proxy.canonical import action_digest
from proxy.interfaces import Analyser, ApprovalService, LogWriter
from proxy.models import ApprovalResult, DecisionSignals, ToolRequest


class CallableLogWriter(LogWriter):
    """Adapter wrapping a callable into the LogWriter protocol."""

    def __init__(self, func: Callable[[str, Dict[str, Any]], Dict[str, Any]]) -> None:
        self.func = func

    def append_event(self, event_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        validate_event_type(event_type)
        res = self.func(event_type, payload)
        return res if isinstance(res, dict) else {"event_type": event_type, "payload": payload}


class CallableAnalyser(Analyser):
    """Adapter wrapping a callable into the Analyser protocol with M3 shape validation."""

    def __init__(self, func: Callable[[Dict[str, Any], str], Dict[str, Any]]) -> None:
        self.func = func

    def analyse_tool_call(self, tool_call: Dict[str, Any], original_goal: str) -> Dict[str, Any]:
        raw = self.func(tool_call, original_goal)
        if not isinstance(raw, dict):
            raise ValueError(f"Analyser output must be a dictionary, got: {type(raw).__name__}")
        clean = {k: v for k, v in raw.items() if k != "model_version"}
        DecisionSignals.from_dict(clean)
        return raw


class CallableApproval(ApprovalService):
    """Adapter wrapping create and verify callables into the ApprovalService protocol."""

    def __init__(
        self,
        create_func: Callable[[ToolRequest], Any],
        verify_func: Callable[[str, ToolRequest], Any],
    ) -> None:
        self.create_func = create_func
        self.verify_func = verify_func

    def create_approval(self, request: ToolRequest) -> Dict[str, Any]:
        res = self.create_func(request)
        if isinstance(res, dict):
            return res
        return {"approval_id": str(res), "request_id": request.request_id}

    def verify_approval(self, code: str, request: ToolRequest) -> ApprovalResult:
        res = self.verify_func(code, request)
        if isinstance(res, ApprovalResult):
            return res
        expected_digest = action_digest(request.tool, request.arguments)
        if isinstance(res, dict):
            approved = bool(res.get("approved"))
            approval_id = str(res.get("approval_id") or f"appr-{request.request_id}")
            digest = str(res.get("action_digest") or expected_digest)
            reason = str(res.get("reason") or ("Approved by external service" if approved else "Rejected by external service"))
            return ApprovalResult(approved=approved, approval_id=approval_id, action_digest=digest, reason=reason)
        if isinstance(res, bool):
            return ApprovalResult(
                approved=res,
                approval_id=f"appr-{request.request_id}",
                action_digest=expected_digest,
                reason="Approved by external service" if res else "Rejected by external service",
            )
        raise ValueError(f"Unexpected verify result type: {type(res).__name__}")
