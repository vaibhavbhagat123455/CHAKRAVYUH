"""Data models for AI Chakravyuh proxy."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

from core.contracts import DECISIONS, POLICY_VERSION, validate_decision

ALLOW = "ALLOW"
HOLD = "HOLD"
DENY = "DENY"

PASS = "PASS"
FLAG = "FLAG"
BLOCK = "BLOCK"
LAYER_STATUSES = frozenset({PASS, FLAG, BLOCK})

SENSITIVE_DATA_RISKS = frozenset({"low", "medium", "high"})

_TOOL_REQUEST_REQUIRED_FIELDS = ("request_id", "tool", "arguments", "purpose", "scenario_id")
_DECISION_SIGNALS_REQUIRED_FIELDS = (
    "prompt_injection",
    "goal_drift",
    "sensitive_data_risk",
    "risk_score",
    "recommended_action",
    "reason",
)


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


@dataclass(frozen=True)
class Decision:
    """Frozen contract representing the pure deterministic checkpoint output."""

    request_id: str
    decision: str
    evidence_id: str
    reason: str
    policy_version: str = POLICY_VERSION
    risk_signals: Optional[Dict[str, Any]] = None
    rule_id: Optional[str] = None

    def __post_init__(self) -> None:
        validate_decision(self.decision)
        for field_name in ("request_id", "evidence_id", "reason", "policy_version"):
            val = getattr(self, field_name)
            if not isinstance(val, str) or not val.strip():
                raise ValueError(f"Field '{field_name}' must be a non-empty string, got: {val!r}")

    def to_dict(self) -> Dict[str, Any]:
        """Convert decision to dictionary matching schemas/decision.schema.json exactly."""
        return {
            "request_id": self.request_id,
            "decision": self.decision,
            "evidence_id": self.evidence_id,
            "reason": self.reason,
            "policy_version": self.policy_version,
        }


@dataclass(frozen=True)
class LayerResult:
    """Evaluation result for one of the defense layers."""

    layer_id: str
    status: str
    reason: str
    evidence_id: str

    def __post_init__(self) -> None:
        if self.status not in LAYER_STATUSES:
            raise ValueError(f"Invalid layer status '{self.status}', must be one of {sorted(LAYER_STATUSES)}")
        for field_name in ("layer_id", "reason", "evidence_id"):
            val = getattr(self, field_name)
            if not isinstance(val, str) or not val.strip():
                raise ValueError(f"Field '{field_name}' must be a non-empty string, got: {val!r}")

    def to_dict(self) -> Dict[str, Any]:
        """Convert LayerResult to dictionary."""
        return {
            "layer_id": self.layer_id,
            "status": self.status,
            "reason": self.reason,
            "evidence_id": self.evidence_id,
        }


@dataclass(frozen=True)
class DecisionSignals:
    """Advisory signals returned by the AI threat analyser."""

    prompt_injection: bool
    goal_drift: bool
    sensitive_data_risk: str
    risk_score: float
    recommended_action: str
    reason: str

    def __post_init__(self) -> None:
        if not isinstance(self.prompt_injection, bool):
            raise ValueError(f"prompt_injection must be a bool, got: {type(self.prompt_injection).__name__}")
        if not isinstance(self.goal_drift, bool):
            raise ValueError(f"goal_drift must be a bool, got: {type(self.goal_drift).__name__}")
        if self.sensitive_data_risk not in SENSITIVE_DATA_RISKS:
            raise ValueError(
                f"sensitive_data_risk must be one of {sorted(SENSITIVE_DATA_RISKS)}, got: {self.sensitive_data_risk!r}"
            )
        if not isinstance(self.risk_score, (int, float)) or not (0.0 <= float(self.risk_score) <= 1.0):
            raise ValueError(f"risk_score must be a float in [0.0, 1.0], got: {self.risk_score!r}")
        validate_decision(self.recommended_action)
        if not isinstance(self.reason, str) or not self.reason.strip():
            raise ValueError(f"reason must be a non-empty string, got: {self.reason!r}")

    def to_dict(self) -> Dict[str, Any]:
        """Convert DecisionSignals to dictionary."""
        return {
            "prompt_injection": self.prompt_injection,
            "goal_drift": self.goal_drift,
            "sensitive_data_risk": self.sensitive_data_risk,
            "risk_score": float(self.risk_score),
            "recommended_action": self.recommended_action,
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> DecisionSignals:
        """Create DecisionSignals from dictionary with validation."""
        if not isinstance(data, dict):
            raise ValueError("Input data must be a dictionary")

        unknown = set(data.keys()) - set(_DECISION_SIGNALS_REQUIRED_FIELDS)
        if unknown:
            raise ValueError(f"Unknown fields in DecisionSignals: {sorted(unknown)}")

        missing = [f for f in _DECISION_SIGNALS_REQUIRED_FIELDS if f not in data]
        if missing:
            raise ValueError(f"Missing required fields in DecisionSignals: {missing}")

        return cls(
            prompt_injection=data["prompt_injection"],
            goal_drift=data["goal_drift"],
            sensitive_data_risk=data["sensitive_data_risk"],
            risk_score=data["risk_score"],
            recommended_action=data["recommended_action"],
            reason=data["reason"],
        )


@dataclass(frozen=True)
class ApprovalResult:
    """Result of human authorization verification."""

    approved: bool
    approval_id: str
    action_digest: str
    reason: str

    def __post_init__(self) -> None:
        if not isinstance(self.approved, bool):
            raise ValueError(f"approved must be a bool, got: {type(self.approved).__name__}")
        for field_name in ("approval_id", "action_digest", "reason"):
            val = getattr(self, field_name)
            if not isinstance(val, str) or not val.strip():
                raise ValueError(f"Field '{field_name}' must be a non-empty string, got: {val!r}")

    def to_dict(self) -> Dict[str, Any]:
        """Convert ApprovalResult to dictionary."""
        return {
            "approved": self.approved,
            "approval_id": self.approval_id,
            "action_digest": self.action_digest,
            "reason": self.reason,
        }
