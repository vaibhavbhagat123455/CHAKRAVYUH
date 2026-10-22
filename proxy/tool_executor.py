"""Synthetic tools. No real external side effect is permitted."""

from __future__ import annotations

from typing import Any, Callable


class ToolExecutionError(RuntimeError):
    pass


class SimulatedToolExecutor:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self._tools: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
            "summarize_document": self._summarize,
            "send_email": self._simulate_transfer,
            "upload_file": self._simulate_transfer,
            "http_post": self._simulate_transfer,
            "export_records": self._simulate_transfer,
        }

    def execute(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if tool not in self._tools:
            raise ToolExecutionError(f"unknown simulated tool: {tool}")
        self.calls.append({"tool": tool, "arguments": dict(arguments)})
        return self._tools[tool](dict(arguments))

    @staticmethod
    def _summarize(arguments: dict[str, Any]) -> dict[str, Any]:
        return {"status": "simulated", "summary": "Synthetic document summary generated."}

    @staticmethod
    def _simulate_transfer(arguments: dict[str, Any]) -> dict[str, Any]:
        return {"status": "simulated", "message": "No real transfer was performed."}
