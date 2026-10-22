"""Simulated tool execution engine and registry for AI Chakravyuh proxy."""

from __future__ import annotations

import threading
from typing import Any, Callable, Dict, Mapping, Optional

from proxy.config import ProxyConfig
from proxy.interfaces import ToolExecutor


class ToolTimeout(Exception):
    """Raised when tool execution exceeds configured timeout."""


class ToolNotFound(Exception):
    """Raised when requested tool name is not registered."""


def summarize_document(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Simulate summarizing a document without real I/O."""
    doc = arguments.get("file") or arguments.get("path") or arguments.get("document") or "synthetic_document"
    return {
        "status": "success",
        "simulated": True,
        "message": "simulated, not sent",
        "summary": f"Simulated executive summary for {doc}",
    }


def send_email(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Simulate sending an email without real network I/O."""
    recipient = arguments.get("recipient") or arguments.get("to") or "simulated@example.edu"
    return {
        "status": "success",
        "simulated": True,
        "message": "simulated, not sent",
        "recipient": recipient,
    }


def transfer_records(arguments: Dict[str, Any]) -> Dict[str, Any]:
    """Simulate records transfer without database operations."""
    destination = arguments.get("destination") or arguments.get("recipient") or "archive"
    return {
        "status": "success",
        "simulated": True,
        "message": "simulated, not sent",
        "destination": destination,
    }


DEFAULT_TOOL_REGISTRY: Mapping[str, Callable[[Dict[str, Any]], Dict[str, Any]]] = {
    "summarize_document": summarize_document,
    "send_email": send_email,
    "transfer_records": transfer_records,
}


class SimulatedExecutor(ToolExecutor):
    """Isolated tool executor running simulated tools with strict timeouts."""

    def __init__(
        self,
        registry: Optional[Mapping[str, Callable[[Dict[str, Any]], Dict[str, Any]]]] = None,
        timeout_seconds: Optional[float] = None,
    ) -> None:
        self.registry = dict(registry if registry is not None else DEFAULT_TOOL_REGISTRY)
        if timeout_seconds is None:
            timeout_seconds = ProxyConfig().tool_timeout_seconds
        self.timeout_seconds = float(timeout_seconds)

    def execute(self, tool: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Execute tool in a worker thread and enforce configured timeout."""
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
