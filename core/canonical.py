"""Deterministic canonical hashing for the append-only security log."""

from __future__ import annotations

import hashlib
from typing import Any, Mapping

from .contracts import canonical_json

GENESIS = "GENESIS_AI_CHAKRAVYUH_V1"


def sha256_hex(value: str) -> str:
    """Return the lowercase SHA-256 hex digest of a UTF-8 string."""
    if not isinstance(value, str):
        raise TypeError("value must be a string")
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def genesis_hash() -> str:
    """Return the previous_hash used by the first log entry."""
    return sha256_hex(GENESIS)


def compute_entry_hash(previous_hash: str, event_without_entry_hash: Mapping[str, Any]) -> str:
    """Hash previous_hash + canonical JSON, exactly as documented in core/README.md."""
    if not isinstance(previous_hash, str) or not previous_hash:
        raise ValueError("previous_hash must be a non-empty string")
    if "entry_hash" in event_without_entry_hash:
        raise ValueError("event passed to compute_entry_hash must not contain entry_hash")
    return sha256_hex(previous_hash + canonical_json(dict(event_without_entry_hash)))
