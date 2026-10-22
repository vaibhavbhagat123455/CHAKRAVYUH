"""Canonical identity for an approval-bound tool action."""

from __future__ import annotations

import hashlib
from typing import Any, Mapping

from .contracts import canonical_json


def action_digest(request: Mapping[str, Any]) -> str:
    """Hash every field that can change what the agent is authorising."""
    if not isinstance(request, Mapping):
        raise ValueError("request must be an object")
    if not request.get("request_id") or not request.get("tool"):
        raise ValueError("request must contain request_id and tool")
    if not isinstance(request["arguments"], Mapping):
        raise ValueError("request arguments must be an object")
    material = {
        "request_id": request["request_id"],
        "tool": request["tool"],
        "arguments": dict(request["arguments"]),
        "purpose": request.get("purpose", ""),
        "scenario_id": request.get("scenario_id", ""),
    }
    return hashlib.sha256(canonical_json(material).encode("utf-8")).hexdigest()


__all__ = ["action_digest"]
