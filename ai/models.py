"""Stable, JSON-serialisable contracts shared with the proxy and policy engine."""

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


@dataclass(frozen=True)
class ToolRequest:
    request_id: str
    tool: str
    arguments: Dict[str, Any]
    purpose: str
    scenario_id: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


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
        if not 0.0 <= self.risk_score <= 1.0:
            raise ValueError("risk_score must be between 0 and 1")
        if self.recommended_action not in {"ALLOW", "HOLD", "DENY"}:
            raise ValueError("recommended_action must be ALLOW, HOLD or DENY")

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
