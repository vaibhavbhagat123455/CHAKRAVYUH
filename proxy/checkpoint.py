"""AI interpretation plus deterministic policy checkpoint."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ai.threat_analyser import ThreatAnalyser
from core.append_log import LogWriter
from core.config import configured_log_path
from core.contracts import POLICY_VERSION
from core.policies import evaluate_policy
from core.schemas import Decision, DecisionSignals, ToolRequest


class Checkpoint:
    def __init__(self, log_path: str | Path | None = None, analyser: Any | None = None) -> None:
        self.log = LogWriter(configured_log_path(log_path))
        self.analyser = analyser or ThreatAnalyser()
        self.decisions: dict[str, Decision] = {}

    def evaluate(self, request: ToolRequest, content: str = "") -> Decision:
        # The append-only log is the ring boundary: downstream layers consume
        # the recorded event envelope rather than an in-memory request object.
        request_event = self.log.append(
            "REQUEST_RECEIVED", request.request_id,
            {"request": request.to_dict(), "content": content},
            scenario_id=request.scenario_id,
        )
        ring_request = ToolRequest.from_dict(request_event.payload["request"])
        ring_content = request_event.payload["content"]
        analysis = self.analyser.analyse(ring_content, ring_request.purpose, ring_request)
        analysis_event = self.log.append(
            "AI_ANALYSIS", request.request_id,
            {"request": ring_request.to_dict(), "signals": analysis.to_dict()},
            scenario_id=request.scenario_id, analyser_version=analysis.analyser_version,
        )
        signals = DecisionSignals.from_mapping(analysis_event.payload["signals"])
        decision = evaluate_policy(ring_request, signals, POLICY_VERSION)
        for layer in decision.layer_results:
            self.log.append(
                "LAYER_EVALUATED", request.request_id, {"layer": layer.to_dict()},
                scenario_id=request.scenario_id, evidence_id=layer.evidence_id,
                policy_version=decision.policy_version,
            )
        self.log.append_checkpoint_decision(request, signals, decision)
        self.decisions[request.request_id] = decision
        return decision
