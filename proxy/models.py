"""Data models for AI Chakravyuh proxy."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

_TOOL_REQUEST_REQUIRED_FIELDS = ("request_id", "tool", "arguments", "purpose", "scenario_id")


@dataclass(frozen=True)
class ToolRequest:
    """Frozen contract representing an inbound tool call attempt."""

    request_id: str
    tool: str
    arguments: Dict[str, Any]
    purpose: str
    scenario_id: str

    def to_dict(self) -> Dict[str, Any]:
        """Convert ToolRequest to dictionary matching tool_request.schema.json."""
        return {
            "request_id": self.request_id,
            "tool": self.tool,
            "arguments": self.arguments,
            "purpose": self.purpose,
            "scenario_id": self.scenario_id,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ToolRequest:
        """Create ToolRequest from a raw dictionary with strict validation.

        Raises ValueError on missing fields, unknown fields, empty strings,
        or non-object arguments.
        """
        if not isinstance(data, dict):
            raise ValueError("Input data must be a dictionary")

        # Check unknown fields
        unknown = set(data.keys()) - set(_TOOL_REQUEST_REQUIRED_FIELDS)
        if unknown:
            raise ValueError(f"Unknown fields in ToolRequest: {sorted(unknown)}")

        # Check missing fields
        missing = [f for f in _TOOL_REQUEST_REQUIRED_FIELDS if f not in data]
        if missing:
            raise ValueError(f"Missing required fields in ToolRequest: {missing}")

        # Check string fields are non-empty strings
        for field_name in ("request_id", "tool", "purpose", "scenario_id"):
            val = data[field_name]
            if not isinstance(val, str) or not val.strip():
                raise ValueError(f"Field '{field_name}' must be a non-empty string, got: {val!r}")

        # Check arguments is a dict (JSON object)
        args = data["arguments"]
        if not isinstance(args, dict):
            raise ValueError(f"Field 'arguments' must be an object/dict, got: {type(args).__name__}")

        return cls(
            request_id=data["request_id"],
            tool=data["tool"],
            arguments=dict(data["arguments"]),
            purpose=data["purpose"],
            scenario_id=data["scenario_id"],
        )
