"""Cryptographic hashing and canonical formatting utilities."""

from __future__ import annotations

import hashlib
from typing import Any, Dict

from core.contracts import canonical_json
from proxy.models import ToolRequest

# Re-export core canonical_json directly
__all__ = [
    "canonical_json",
    "sha256_hex",
    "request_fingerprint",
    "action_digest",
]


def sha256_hex(text: str) -> str:
    """Compute standard SHA-256 hex digest of a UTF-8 string."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def request_fingerprint(request: ToolRequest) -> str:
    """Compute reproducible SHA-256 fingerprint of canonical ToolRequest."""
    return sha256_hex(canonical_json(request.to_dict()))


def action_digest(tool: str, arguments: Dict[str, Any]) -> str:
    """Compute SHA-256 action digest bound exclusively to tool name and arguments.

    Ignores metadata such as request_id, purpose, and scenario_id.
    """
    canon = canonical_json({"arguments": arguments, "tool": tool})
    return sha256_hex(canon)
