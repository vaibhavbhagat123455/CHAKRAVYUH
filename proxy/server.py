"""MCP Proxy Server implementation with dependency injection and audit logging."""

from __future__ import annotations

from typing import Any, Dict, Optional

from core.contracts import POLICY_VERSION
from proxy.checkpoint import decide
from proxy.config import ProxyConfig
from proxy.events import ANALYSIS_RECORDED, REQUEST_RECEIVED, emit
from proxy.interfaces import (
    Analyser,
    ApprovalService,
    Clock,
    LogWriter,
    ToolExecutor,
)
from proxy.models import DecisionSignals, ToolRequest
from proxy.policy import get_policy


class ProxyServer:
    """Core MCP security proxy server intercepting and governing tool calls."""

    def __init__(
        self,
        log: LogWriter,
        analyser: Analyser,
        executor: ToolExecutor,
        approval: Optional[ApprovalService] = None,
        config: Optional[ProxyConfig] = None,
        clock: Optional[Clock] = None,
    ) -> None:
        self.log = log
        self.analyser = analyser
        self.executor = executor
        self.approval = approval
        self.config = config if config is not None else ProxyConfig()
        self.clock = clock
        self.policy_version = POLICY_VERSION
        self.policy = get_policy(self.policy_version)

    def handle_tool_call(self, request: ToolRequest) -> Dict[str, Any]:
        """Handle incoming tool call attempt with AI analysis and safe fallback."""
        # 1. Initial request audit event
        emit(self.log, REQUEST_RECEIVED, request.request_id, request.to_dict())

        # 2. Call analyser with safe fallback
        signals: Optional[DecisionSignals] = None
        analyser_failed = False
        error_type: Optional[str] = None
        model_version: Optional[str] = None

        try:
            raw_analysis = self.analyser.analyse_tool_call(request.to_dict(), request.purpose)
            if not isinstance(raw_analysis, dict):
                raise ValueError(f"Analyser output must be a dict, got: {type(raw_analysis).__name__}")
            model_version = raw_analysis.get("model_version")
            clean_data = dict(raw_analysis)
            clean_data.pop("model_version", None)
            signals = DecisionSignals.from_dict(clean_data)
        except Exception as exc:
            analyser_failed = True
            error_type = type(exc).__name__
            signals = None

        analysis_payload: Dict[str, Any] = {
            "analyser_failed": analyser_failed,
            "signals": signals.to_dict() if signals is not None else None,
        }
        if analyser_failed:
            analysis_payload["error_type"] = error_type
        if model_version is not None:
            analysis_payload["model_version"] = model_version

        emit(self.log, ANALYSIS_RECORDED, request.request_id, analysis_payload)

        # 3. Deterministic policy decision
        decision = decide(request, signals, policy_version=self.policy_version, policy=self.policy)

        return {
            "status": "decided",
            "decision": decision.decision,
            "evidence_id": decision.evidence_id,
            "rule_id": decision.rule_id,
            "reason": decision.reason,
        }
