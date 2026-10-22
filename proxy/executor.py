"""Simulated tool execution engine and registry for AI Chakravyuh proxy."""

from __future__ import annotations

import threading
from typing import Any, Callable, Dict, Mapping, Optional

from proxy.config import ProxyConfig
from proxy.interfaces import ToolExecutor
from proxy.models import ALLOW, Decision
from proxy.pending import PendingRecord


class ToolTimeout(Exception):
    """Raised when tool execution exceeds configured timeout."""


class ToolNotFound(Exception):
    """Raised when requested tool name is not registered."""


def summarize_document(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Blocked direct invocation."""
    raise PermissionError("Tool execution is reachable only through the proxy.")


def send_email(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Blocked direct invocation."""
    raise PermissionError("Tool execution is reachable only through the proxy.")


def transfer_records(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Blocked direct invocation."""
    raise PermissionError("Tool execution is reachable only through the proxy.")


def _summarize_document(arguments: Dict[str, Any]) -> Dict[str, Any]:
    doc = arguments.get("file") or arguments.get("path") or arguments.get("document") or "synthetic_document"
    return {"status": "success", "simulated": True, "message": "simulated, not sent", "summary": f"Simulated executive summary for {doc}"}


def _send_email(arguments: Dict[str, Any]) -> Dict[str, Any]:
    recipient = arguments.get("recipient") or arguments.get("to") or "simulated@example.edu"
    return {"status": "success", "simulated": True, "message": "simulated, not sent", "recipient": recipient}


def _transfer_records(arguments: Dict[str, Any]) -> Dict[str, Any]:
    destination = arguments.get("destination") or arguments.get("recipient") or "archive"
    return {"status": "success", "simulated": True, "message": "simulated, not sent", "destination": destination}


DEFAULT_TOOL_REGISTRY: Mapping[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = {
    "summarize_document": _summarize_document,
    "send_email": _send_email,
    "transfer_records": _transfer_records,
}


class SimulatedExecutor(ToolExecutor):
    """Isolated tool executor running simulated tools with strict timeouts and authorization checks."""

    def __init__(
        self,
        registry: Optional[Mapping[str, Callable[[Dict[str, Any]], Dict[str, Any]]]] = None,
        timeout_seconds: Optional[float] = None,
    ) -> None:
        self.registry = dict(registry if registry is not None else DEFAULT_TOOL_REGISTRY)
        if timeout_seconds is None:
            timeout_seconds = ProxyConfig().tool_timeout_seconds
        self.timeout_seconds = float(timeout_seconds)

    def execute(
        self,
        tool: str,
        arguments: Dict[str, Any],
        auth_token: Optional[Any] = None,
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Execute tool with required authorization token verification."""
        if auth_token is None:
            raise PermissionError("Authorisation token required for tool execution.")

        if isinstance(auth_token, Decision):
            if auth_token.decision != ALLOW:
                raise PermissionError(f"Authorisation token decision '{auth_token.decision}' is not ALLOW.")
            if request_id is not None and auth_token.request_id != request_id:
                raise PermissionError(f"Token request_id '{auth_token.request_id}' does not match '{request_id}'.")
        elif isinstance(auth_token, PendingRecord):
            if request_id is not None and auth_token.request.request_id != request_id:
                raise PermissionError(f"Pending record request_id '{auth_token.request.request_id}' does not match '{request_id}'.")
            if auth_token.request.tool != tool:
                raise PermissionError(f"Pending record tool '{auth_token.request.tool}' does not match '{tool}'.")
        else:
            raise PermissionError(f"Invalid authorisation token type: {type(auth_token).__name__}")

        if tool not in self.registry:
            raise ToolNotFound(f"Tool '{tool}' not found in executor registry")

        tool_fn = self.registry[tool]
        output: list[Dict[str, Any]] = []
        errors: list[Exception] = []

        def worker() -> None:
            try:
                output.append(tool_fn(arguments))
            except Exception as exc:
                errors.append(exc)

        thread = threading.Thread(target=worker, daemon=True)
        thread.start()
        thread.join(timeout=self.timeout_seconds)

        if thread.is_alive():
            raise ToolTimeout(f"Tool '{tool}' execution timed out after {self.timeout_seconds}s")
        if errors:
            raise errors[0]
        return output[0]
