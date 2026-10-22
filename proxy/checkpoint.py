"""AI interpretation plus deterministic policy checkpoint."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ai.threat_analyser import ThreatAnalyser
from core.append_log import LogWriter
from core.contracts import POLICY_VERSION
from core.policies import evaluate_policy
from core.schemas import Decision, DecisionSignals, ToolRequest


class Checkpoint:
    def __init__(self, log_path: str | Path = "data/security_log.jsonl", analyser: Any | None = None) -> None:
        self.log = LogWriter(log_path)
        self.analyser = analyser or ThreatAnalyser()
        self.decisions: dict[str, Decision] = {}

    def evaluate(self, request: ToolRequest, content: str = "") -> Decision:
        self.log.append("REQUEST_RECEIVED", request.request_id, {"request": request.to_dict()}, scenario_id=request.scenario_id)
        analysis = self.analyser.analyse(content, request.purpose, request)
        signals = DecisionSignals.from_mapping(analysis.to_dict())
        self.log.append(
            "AI_ANALYSIS", request.request_id,
            {"request": request.to_dict(), "signals": signals.to_dict()},
            scenario_id=request.scenario_id, analyser_version=signals.analyser_version,
        )
        decision = evaluate_policy(request, signals, POLICY_VERSION)
        for layer in decision.layer_results:
            self.log.append(
                "LAYER_EVALUATED", request.request_id, {"layer": layer.to_dict()},
                scenario_id=request.scenario_id, evidence_id=layer.evidence_id,
                policy_version=decision.policy_version,
            )
        self.log.append_checkpoint_decision(request, signals, decision)
        self.decisions[request.request_id] = decision
        return decision
