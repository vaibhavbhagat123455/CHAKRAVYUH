"""Stable, JSON-serialisable contracts shared with the proxy and policy engine."""

from dataclasses import asdict, dataclass, field
import math
from typing import Any, Dict, List


@dataclass(frozen=True)
class ToolRequest:
    request_id: str
    tool: str
    arguments: Dict[str, Any]
    purpose: str
    scenario_id: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def __post_init__(self) -> None:
        for field_name in ("request_id", "tool", "purpose", "scenario_id"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{field_name} must be a non-empty string")
        if not isinstance(self.arguments, dict):
            raise ValueError("arguments must be a JSON object")


@dataclass(frozen=True)
class AnalysisResult:
    prompt_injection: bool
    goal_drift: bool
    sensitive_data_risk: str
    risk_score: float
    recommended_action: str
    reason: str
    evidence: List[str] = field(default_factory=list)
    analyser_version: str = "rules-v1"

    def __post_init__(self) -> None:
        if self.sensitive_data_risk not in {"low", "medium", "high"}:
            raise ValueError("sensitive_data_risk must be low, medium or high")
        if not math.isfinite(self.risk_score) or not 0.0 <= self.risk_score <= 1.0:
            raise ValueError("risk_score must be between 0 and 1")
        if self.recommended_action not in {"ALLOW", "HOLD", "DENY"}:
            raise ValueError("recommended_action must be ALLOW, HOLD or DENY")
        if not isinstance(self.reason, str) or not self.reason.strip():
            raise ValueError("reason must be a non-empty string")
        if not isinstance(self.evidence, list) or not all(isinstance(item, str) for item in self.evidence):
            raise ValueError("evidence must be a list of strings")

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Scenario:
    scenario_id: str
    name: str
    original_goal: str
    content: str
    tool_request: ToolRequest
    expected_decision: str
    expected_signals: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["tool_request"] = self.tool_request.to_dict()
        return data
