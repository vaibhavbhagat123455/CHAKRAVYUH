"""Frozen dataclass contracts shared by every AI Chakravyuh module."""

from __future__ import annotations

import math
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping

from .canonical import sha256_hex
from .contracts import DECISIONS, LOG_EVENT_TYPES, POLICY_VERSION, canonical_json, validate_decision, validate_event_type

RISK_LEVELS = frozenset({"low", "medium", "high"})
LAYER_IDS = ("DWAAR", "PEHCHAAN", "SMRITI", "SANKALP", "ASTRA", "MARYADA", "DRISHTI")
LAYER_STATUSES = frozenset({"PASS", "REVIEW", "BLOCK", "SKIP"})
HASH_RE = re.compile(r"^[0-9a-f]{64}$")


def _require_text(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be a non-empty string")
    return value


def _require_mapping(value: Any, field_name: str) -> dict[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{field_name} must be a JSON object")
    return dict(value)


def _require_hash(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not HASH_RE.match(value):
        raise ValueError(f"{field_name} must be a 64-character lowercase SHA-256 hex digest")
    return value


def _require_utc_timestamp(value: Any, field_name: str = "timestamp") -> str:
    _require_text(value, field_name)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field_name} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError(f"{field_name} must use UTC")
    return value


def _coerce_string_list(value: Any, field_name: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or not all(isinstance(item, str) for item in value):
        raise ValueError(f"{field_name} must be a list of strings")
    return tuple(value)


@dataclass(frozen=True)
class ToolRequest:
    request_id: str
    tool: str
    arguments: dict[str, Any]
    purpose: str
    scenario_id: str

    def __post_init__(self) -> None:
        for field_name in ("request_id", "tool", "purpose", "scenario_id"):
            _require_text(getattr(self, field_name), field_name)
        object.__setattr__(self, "arguments", _require_mapping(self.arguments, "arguments"))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def fingerprint(self) -> str:
        return sha256_hex(canonical_json(self.to_dict()))

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "ToolRequest":
        raw = _require_mapping(raw, "tool_request")
        required = {"request_id", "tool", "arguments", "purpose", "scenario_id"}
        missing = required - raw.keys()
        if missing:
            raise ValueError(f"tool_request is missing fields: {sorted(missing)}")
        unknown = raw.keys() - required
        if unknown:
            raise ValueError(f"tool_request has unknown fields: {sorted(unknown)}")
        return cls(
            request_id=raw["request_id"],
            tool=raw["tool"],
            arguments=raw["arguments"],
            purpose=raw["purpose"],
            scenario_id=raw["scenario_id"],
        )


@dataclass(frozen=True)
class DecisionSignals:
    prompt_injection: bool
    goal_drift: bool
    sensitive_data_risk: str
    risk_score: float
    recommended_action: str
    reason: str
    evidence: tuple[str, ...] = ()
    analyser_version: str = "rules-v1"

    def __post_init__(self) -> None:
        for field_name in ("prompt_injection", "goal_drift"):
            if not isinstance(getattr(self, field_name), bool):
                raise ValueError(f"{field_name} must be a boolean")
        if self.sensitive_data_risk not in RISK_LEVELS:
            raise ValueError(f"sensitive_data_risk must be one of {sorted(RISK_LEVELS)}")
        if not isinstance(self.risk_score, (int, float)) or not math.isfinite(self.risk_score):
            raise ValueError("risk_score must be a finite number")
        if not 0.0 <= float(self.risk_score) <= 1.0:
            raise ValueError("risk_score must be between 0 and 1")
        validate_decision(self.recommended_action)
        _require_text(self.reason, "reason")
        _require_text(self.analyser_version, "analyser_version")
        object.__setattr__(self, "evidence", _coerce_string_list(self.evidence, "evidence"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "prompt_injection": self.prompt_injection,
            "goal_drift": self.goal_drift,
            "sensitive_data_risk": self.sensitive_data_risk,
            "risk_score": float(self.risk_score),
            "recommended_action": self.recommended_action,
            "reason": self.reason,
            "evidence": list(self.evidence),
            "analyser_version": self.analyser_version,
        }

    @classmethod
    def from_mapping(cls, raw: Mapping[str, Any]) -> "DecisionSignals":
        raw = _require_mapping(raw, "signals")
        required = {
            "prompt_injection",
            "goal_drift",
            "sensitive_data_risk",
            "risk_score",
            "recommended_action",
            "reason",
        }
        missing = required - raw.keys()
        if missing:
            raise ValueError(f"signals are missing fields: {sorted(missing)}")
        return cls(
            prompt_injection=raw["prompt_injection"],
            goal_drift=raw["goal_drift"],
            sensitive_data_risk=raw["sensitive_data_risk"],
            risk_score=raw["risk_score"],
            recommended_action=raw["recommended_action"],
            reason=raw["reason"],
            evidence=raw.get("evidence", ()),
            analyser_version=raw.get("analyser_version", "rules-v1"),
        )


AnalysisSignals = DecisionSignals


@dataclass(frozen=True)
class LayerResult:
    layer_id: str
    status: str
    reason: str
    evidence_id: str

    def __post_init__(self) -> None:
        if self.layer_id not in LAYER_IDS:
            raise ValueError(f"layer_id must be one of {list(LAYER_IDS)}")
        if self.status not in LAYER_STATUSES:
            raise ValueError(f"status must be one of {sorted(LAYER_STATUSES)}")
        _require_text(self.reason, "reason")
        _require_text(self.evidence_id, "evidence_id")

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "LayerResult":
        raw = _require_mapping(raw, "layer_result")
        return cls(
            layer_id=raw["layer_id"],
            status=raw["status"],
            reason=raw["reason"],
            evidence_id=raw["evidence_id"],
        )


@dataclass(frozen=True)
class Decision:
    request_id: str
    decision: str
    evidence_id: str
    reason: str
    policy_version: str
    signals: DecisionSignals | None = None
    policy_facts: dict[str, Any] = field(default_factory=dict)
    layer_results: tuple[LayerResult, ...] = ()

    def __post_init__(self) -> None:
        _require_text(self.request_id, "request_id")
        validate_decision(self.decision)
        _require_text(self.evidence_id, "evidence_id")
        _require_text(self.reason, "reason")
        _require_text(self.policy_version, "policy_version")
        if self.signals is not None and not isinstance(self.signals, DecisionSignals):
            raise ValueError("signals must be a DecisionSignals instance or None")
        object.__setattr__(self, "policy_facts", _require_mapping(self.policy_facts, "policy_facts"))
        if not isinstance(self.layer_results, (list, tuple)) or not all(
            isinstance(item, LayerResult) for item in self.layer_results
        ):
            raise ValueError("layer_results must contain LayerResult objects")
        object.__setattr__(self, "layer_results", tuple(self.layer_results))

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "request_id": self.request_id,
            "decision": self.decision,
            "evidence_id": self.evidence_id,
            "reason": self.reason,
            "policy_version": self.policy_version,
        }
        if self.signals is not None:
            data["signals"] = self.signals.to_dict()
        if self.policy_facts:
            data["policy_facts"] = dict(self.policy_facts)
        if self.layer_results:
            data["layer_results"] = [layer.to_dict() for layer in self.layer_results]
        return data

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "Decision":
        raw = _require_mapping(raw, "decision")
        signals = raw.get("signals")
        return cls(
            request_id=raw["request_id"],
            decision=raw["decision"],
            evidence_id=raw["evidence_id"],
            reason=raw["reason"],
            policy_version=raw["policy_version"],
            signals=DecisionSignals.from_mapping(signals) if signals is not None else None,
            policy_facts=raw.get("policy_facts", {}),
            layer_results=tuple(LayerResult.from_dict(item) for item in raw.get("layer_results", ())),
        )


@dataclass(frozen=True)
class LogEvent:
    sequence: int
    event_id: str
    timestamp: str
    event_type: str
    request_id: str
    payload: dict[str, Any]
    previous_hash: str
    entry_hash: str
    scenario_id: str | None = None
    decision: str | None = None
    evidence_id: str | None = None
    policy_version: str | None = None
    analyser_version: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.sequence, int) or isinstance(self.sequence, bool) or self.sequence < 1:
            raise ValueError("sequence must be an integer >= 1")
        for field_name in ("event_id", "request_id"):
            _require_text(getattr(self, field_name), field_name)
        _require_utc_timestamp(self.timestamp)
        validate_event_type(self.event_type)
        object.__setattr__(self, "payload", _require_mapping(self.payload, "payload"))
        _require_hash(self.previous_hash, "previous_hash")
        _require_hash(self.entry_hash, "entry_hash")
        if self.decision is not None:
            validate_decision(self.decision)
        for field_name in ("scenario_id", "evidence_id", "policy_version", "analyser_version"):
            value = getattr(self, field_name)
            if value is not None:
                _require_text(value, field_name)

    def to_dict(self, *, include_entry_hash: bool = True) -> dict[str, Any]:
        data: dict[str, Any] = {
            "sequence": self.sequence,
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "request_id": self.request_id,
            "payload": dict(self.payload),
            "previous_hash": self.previous_hash,
        }
        for field_name in (
            "scenario_id",
            "decision",
            "evidence_id",
            "policy_version",
            "analyser_version",
        ):
            value = getattr(self, field_name)
            if value is not None:
                data[field_name] = value
        if include_entry_hash:
            data["entry_hash"] = self.entry_hash
        return data

    def canonical_dict(self) -> dict[str, Any]:
        return self.to_dict(include_entry_hash=False)

    def to_json_line(self) -> str:
        return canonical_json(self.to_dict()) + "\n"

    @classmethod
    def from_dict(cls, raw: Mapping[str, Any]) -> "LogEvent":
        raw = _require_mapping(raw, "log_event")
        required = {"sequence", "event_id", "timestamp", "event_type", "request_id", "payload", "previous_hash", "entry_hash"}
        missing = required - raw.keys()
        if missing:
            raise ValueError(f"log_event is missing fields: {sorted(missing)}")
        return cls(
            sequence=raw["sequence"],
            event_id=raw["event_id"],
            timestamp=raw["timestamp"],
            event_type=raw["event_type"],
            request_id=raw["request_id"],
            payload=raw["payload"],
            previous_hash=raw["previous_hash"],
            entry_hash=raw["entry_hash"],
            scenario_id=raw.get("scenario_id"),
            decision=raw.get("decision"),
            evidence_id=raw.get("evidence_id"),
            policy_version=raw.get("policy_version"),
            analyser_version=raw.get("analyser_version"),
        )


@dataclass(frozen=True)
class VerificationError:
    line: int
    code: str
    message: str
    sequence: int | None = None
    event_id: str | None = None
    expected: Any = None
    actual: Any = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "line": self.line,
            "code": self.code,
            "message": self.message,
        }
        if self.sequence is not None:
            data["sequence"] = self.sequence
        if self.event_id is not None:
            data["event_id"] = self.event_id
        if self.expected is not None:
            data["expected"] = self.expected
        if self.actual is not None:
            data["actual"] = self.actual
        return data


@dataclass(frozen=True)
class VerificationResult:
    valid: bool
    log_path: str
    entries_checked: int
    genesis: str
    errors: tuple[VerificationError, ...] = ()

    @property
    def first_invalid(self) -> VerificationError | None:
        return self.errors[0] if self.errors else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "log_path": self.log_path,
            "entries_checked": self.entries_checked,
            "genesis": self.genesis,
            "first_invalid": self.first_invalid.to_dict() if self.first_invalid else None,
            "errors": [error.to_dict() for error in self.errors],
        }


@dataclass(frozen=True)
class ReplayDecision:
    request_id: str
    recorded: str
    replayed: str
    match: bool
    evidence_id: str | None = None
    evidence_id_match: bool | None = None
    expected: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "request_id": self.request_id,
            "recorded": self.recorded,
            "replayed": self.replayed,
            "match": self.match,
        }
        if self.evidence_id is not None:
            data["evidence_id"] = self.evidence_id
        if self.evidence_id_match is not None:
            data["evidence_id_match"] = self.evidence_id_match
        if self.expected is not None:
            data["expected"] = self.expected
        return data


@dataclass(frozen=True)
class ReplayResult:
    valid: bool
    log_verified: bool
    policy_version: str
    events_replayed: int
    decision_digest: str
    decisions: tuple[ReplayDecision, ...] = ()
    mismatches: tuple[ReplayDecision, ...] = ()
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "valid": self.valid,
            "log_verified": self.log_verified,
            "policy_version": self.policy_version,
            "events_replayed": self.events_replayed,
            "decision_digest": self.decision_digest,
            "decisions": [decision.to_dict() for decision in self.decisions],
            "mismatches": [decision.to_dict() for decision in self.mismatches],
        }
        if self.error is not None:
            data["error"] = self.error
        return data


__all__ = [
    "AnalysisSignals",
    "Decision",
    "DecisionSignals",
    "LayerResult",
    "LogEvent",
    "ReplayDecision",
    "ReplayResult",
    "ToolRequest",
    "VerificationError",
    "VerificationResult",
    "DECISIONS",
    "LOG_EVENT_TYPES",
    "POLICY_VERSION",
    "RISK_LEVELS",
    "LAYER_IDS",
    "LAYER_STATUSES",
]
