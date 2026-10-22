"""Append-only, hash-chained security log."""

from __future__ import annotations

import json
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping

from .canonical import GENESIS, compute_entry_hash, genesis_hash
from .contracts import canonical_json, validate_event_type
from .locking import FileLock
from .schemas import Decision, DecisionSignals, LogEvent, ToolRequest

SENSITIVE_KEYS = frozenset(
    {
        "code",
        "approval_code",
        "raw_code",
        "password",
        "passwd",
        "token",
        "access_token",
        "secret",
        "api_key",
        "private_key",
    }
)
REDACTED = "[REDACTED]"
_NORMALISED_SENSITIVE_KEYS = frozenset(re.sub(r"[^a-z0-9]", "", key) for key in SENSITIVE_KEYS)


def _is_sensitive_key(key: str) -> bool:
    return re.sub(r"[^a-z0-9]", "", key.lower()) in _NORMALISED_SENSITIVE_KEYS


class LogCorruptionError(ValueError):
    """Raised when the existing log tail cannot safely be extended."""


def utc_now_iso() -> str:
    """Return an ISO-8601 UTC timestamp with millisecond precision."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _default_event_id(sequence: int) -> str:
    return f"evt-{sequence:06d}-{uuid.uuid4().hex[:12]}"


def redact_payload(value: Any) -> Any:
    """Recursively redact secret-bearing keys before anything is persisted."""
    if isinstance(value, Mapping):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            if isinstance(key, str) and _is_sensitive_key(key):
                redacted[key] = REDACTED
            else:
                redacted[str(key)] = redact_payload(item)
        return redacted
    if isinstance(value, (list, tuple)):
        return [redact_payload(item) for item in value]
    return value


def read_last_event(path: str | Path) -> LogEvent | None:
    """Read and validate the final event, returning None for an empty log."""
    path = Path(path)
    if not path.exists():
        return None
    text = path.read_text(encoding="utf-8")
    if not text.strip():
        return None
    if not text.endswith("\n"):
        raise LogCorruptionError("security log must end with a newline")
    lines = text.splitlines()
    if not lines or not lines[-1].strip():
        raise LogCorruptionError("security log ends with a blank line")
    try:
        raw = json.loads(lines[-1])
    except json.JSONDecodeError as exc:
        raise LogCorruptionError(f"last log entry is not valid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise LogCorruptionError("last log entry must be a JSON object")
    try:
        return LogEvent.from_dict(raw)
    except (KeyError, TypeError, ValueError) as exc:
        raise LogCorruptionError(f"last log entry violates the log contract: {exc}") from exc


class LogWriter:
    """Append validated events while preserving the hash chain."""

    def __init__(
        self,
        path: str | Path,
        *,
        clock: Callable[[], str] = utc_now_iso,
        id_factory: Callable[[int], str] = _default_event_id,
        lock_factory: Callable[[Path], FileLock] = FileLock,
    ) -> None:
        self.path = Path(path)
        self._clock = clock
        self._id_factory = id_factory
        self._lock_factory = lock_factory

    def append(
        self,
        event_type: str,
        request_id: str,
        payload: Mapping[str, Any] | None = None,
        *,
        scenario_id: str | None = None,
        decision: str | None = None,
        evidence_id: str | None = None,
        policy_version: str | None = None,
        analyser_version: str | None = None,
        event_id: str | None = None,
        timestamp: str | None = None,
    ) -> LogEvent:
        validate_event_type(event_type)
        if payload is None:
            payload = {}
        if not isinstance(payload, Mapping):
            raise ValueError("payload must be a JSON object")
        payload = redact_payload(payload)
        try:
            canonical_json(payload)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"payload must be JSON-serialisable: {exc}") from exc

        if event_type == "CHECKPOINT_DECISION":
            if decision is None or evidence_id is None or policy_version is None:
                raise ValueError(
                    "CHECKPOINT_DECISION requires decision, evidence_id and policy_version"
                )
            if "request" not in payload or "signals" not in payload:
                raise ValueError(
                    "CHECKPOINT_DECISION payload must contain request and signals for replay"
                )

        with self._lock_factory(self.path):
            self.path.parent.mkdir(parents=True, exist_ok=True)
            if self.path.exists() and self.path.stat().st_size:
                from .verify import verify_log

                existing = verify_log(self.path)
                if not existing.valid:
                    first = existing.first_invalid
                    detail = first.message if first else "unknown error"
                    raise LogCorruptionError(f"refusing to extend an invalid log: {detail}")
                if event_id is not None:
                    for line in self.path.read_text(encoding="utf-8").splitlines():
                        if line.strip() and json.loads(line).get("event_id") == event_id:
                            raise ValueError(f"event_id already exists in the log: {event_id}")
            last = read_last_event(self.path)
            if last is None:
                sequence = 1
                previous_hash = genesis_hash()
            else:
                sequence = last.sequence + 1
                previous_hash = last.entry_hash

            event_id = event_id or self._id_factory(sequence)
            timestamp = timestamp or self._clock()
            draft = {
                "sequence": sequence,
                "event_id": event_id,
                "timestamp": timestamp,
                "event_type": event_type,
                "request_id": request_id,
                "payload": payload,
                "previous_hash": previous_hash,
            }
            if scenario_id is not None:
                draft["scenario_id"] = scenario_id
            if decision is not None:
                draft["decision"] = decision
            if evidence_id is not None:
                draft["evidence_id"] = evidence_id
            if policy_version is not None:
                draft["policy_version"] = policy_version
            if analyser_version is not None:
                draft["analyser_version"] = analyser_version

            entry_hash = compute_entry_hash(previous_hash, draft)
            event = LogEvent(**draft, entry_hash=entry_hash)
            with open(self.path, "a", encoding="utf-8", newline="\n") as handle:
                handle.write(event.to_json_line())
                handle.flush()
                os.fsync(handle.fileno())
            return event

    def append_checkpoint_decision(
        self,
        request: ToolRequest,
        signals: DecisionSignals,
        decision: Decision,
        *,
        event_id: str | None = None,
        timestamp: str | None = None,
    ) -> LogEvent:
        if decision.request_id != request.request_id:
            raise ValueError("decision.request_id must match request.request_id")
        return self.append(
            "CHECKPOINT_DECISION",
            request.request_id,
            {"request": request.to_dict(), "signals": signals.to_dict()},
            scenario_id=request.scenario_id,
            decision=decision.decision,
            evidence_id=decision.evidence_id,
            policy_version=decision.policy_version,
            analyser_version=signals.analyser_version,
            event_id=event_id,
            timestamp=timestamp,
        )


def append_event(
    path: str | Path,
    event_type: str,
    request_id: str,
    payload: Mapping[str, Any] | None = None,
    **kwargs: Any,
) -> LogEvent:
    """Convenience wrapper for callers that do not need to reuse a writer."""
    return LogWriter(path).append(event_type, request_id, payload, **kwargs)


__all__ = [
    "GENESIS",
    "LogCorruptionError",
    "LogWriter",
    "REDACTED",
    "SENSITIVE_KEYS",
    "append_event",
    "read_last_event",
    "redact_payload",
    "utc_now_iso",
]
