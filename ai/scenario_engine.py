"""Load, validate and analyse repeatable synthetic attack scenarios."""

import json
from pathlib import Path
from typing import Dict, Iterable, Union

from .models import Scenario, ToolRequest
from .threat_analyser import ThreatAnalyser


class ScenarioEngine:
    def __init__(self, analyser: ThreatAnalyser | None = None) -> None:
        self.analyser = analyser or ThreatAnalyser()

    def load(self, path: Union[str, Path]) -> Scenario:
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        return self.from_dict(raw)

    @staticmethod
    def from_dict(raw: Dict) -> Scenario:
        required = {"scenario_id", "name", "original_goal", "content", "tool_request", "expected_decision"}
        missing = required - raw.keys()
        if missing:
            raise ValueError(f"scenario is missing fields: {sorted(missing)}")
        request = ToolRequest(**raw["tool_request"])
        if request.scenario_id != raw["scenario_id"]:
            raise ValueError("tool_request.scenario_id must match scenario_id")
        if raw["expected_decision"] not in {"ALLOW", "HOLD", "DENY"}:
            raise ValueError("expected_decision must be ALLOW, HOLD or DENY")
        return Scenario(
            scenario_id=raw["scenario_id"], name=raw["name"], original_goal=raw["original_goal"],
            content=raw["content"], tool_request=request, expected_decision=raw["expected_decision"],
            expected_signals=raw.get("expected_signals", {}), metadata=raw.get("metadata", {}),
        )

    def analyse(self, scenario: Scenario):
        return self.analyser.analyse(scenario.content, scenario.original_goal, scenario.tool_request)

    def run_directory(self, directory: Union[str, Path]) -> Dict[str, object]:
        results = {}
        for path in sorted(Path(directory).glob("*.json")):
            scenario = self.load(path)
            results[scenario.scenario_id] = self.analyse(scenario).to_dict()
        return results
