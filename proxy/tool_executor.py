"""Synthetic tools. No real external side effect is permitted."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Any, Callable

from core.config import ROOT
from core.contracts import canonical_json
from core.pdf_scanner import inspect_pdf


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


class LocalSandboxExecutor(SimulatedToolExecutor):
    """Functional, side-effect-contained executor used by the jury demo.

    It performs real local PDF summarisation and writes transfer intents as
    JSON artifacts. It never sends network traffic, emails, uploads or exports
    outside the sandbox directory.
    """

    def __init__(self, output_dir: str | Path | None = None) -> None:
        super().__init__()
        self.output_dir = Path(output_dir or os.getenv("TOOL_OUTPUT_DIR", ROOT / "data" / "tool-effects"))

    def execute(self, tool: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if tool == "summarize_document":
            self.calls.append({"tool": tool, "arguments": dict(arguments)})
            filename = arguments.get("file")
            if isinstance(filename, str):
                candidate = ROOT / "data" / "fixtures" / Path(filename).name
                if candidate.is_file() and candidate.suffix.lower() == ".pdf":
                    inspection = inspect_pdf(candidate)
                    return {"status": "completed", "summary": inspection.extracted_text[:500],
                            "document_sha256": inspection.sha256, "pages": inspection.page_count}
            return {"status": "completed", "summary": "No readable PDF content was supplied."}
        if tool in {"send_email", "upload_file", "http_post", "export_records"}:
            self.calls.append({"tool": tool, "arguments": dict(arguments)})
            material = canonical_json({"tool": tool, "arguments": arguments})
            artifact_id = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
            path = self.output_dir / f"{tool}-{artifact_id}.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps({"tool": tool, "arguments": arguments, "status": "sandboxed"},
                                       indent=2, sort_keys=True) + "\n", encoding="utf-8")
            return {"status": "sandboxed", "artifact": str(path), "artifact_sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        raise ToolExecutionError(f"unknown sandbox tool: {tool}")
