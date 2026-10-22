"""MCP Proxy Server implementation with dependency injection and audit logging."""

from __future__ import annotations

from typing import Any, Dict, Optional

from core.contracts import POLICY_VERSION
from proxy.checkpoint import decide, layers
from proxy.config import ProxyConfig
from proxy.events import (
    ANALYSIS_RECORDED,
    CHECKPOINT_DECISION,
    LAYER_EVALUATED,
    REQUEST_RECEIVED,
    TOOL_BLOCKED,
    TOOL_COMPLETED,
    TOOL_STARTED,
    TOOL_TIMEOUT,
    emit,
)
from proxy.interfaces import (
    Analyser,
    ApprovalService,
    Clock,
    LogWriter,
    ToolExecutor,
)
from proxy.jsonrpc import POLICY_DENIED, TOOL_FAILED, error_response, success_response
from proxy.models import ALLOW, DENY, HOLD, DecisionSignals, ToolRequest
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

    def handle_tool_call(
        self,
        request: ToolRequest,
        rpc_id: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """Handle incoming tool call attempt with full audit trail and guarded execution."""
        effective_rpc_id = rpc_id if rpc_id is not None else request.request_id

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

        # 4. Seven defense layers trail
        layer_results = layers(request, signals, decision, self.policy)
        for lr in layer_results:
            layer_payload = {
                "layer_id": lr.layer_id,
                "status": lr.status,
                "reason": lr.reason,
                "evidence_id": lr.evidence_id,
            }
            emit(self.log, LAYER_EVALUATED, request.request_id, layer_payload)

        # 5. Checkpoint decision audit event BEFORE any execution
        decision_payload = {
            "decision": decision.decision,
            "evidence_id": decision.evidence_id,
            "rule_id": decision.rule_id,
            "reason": decision.reason,
            "policy_version": decision.policy_version,
            "signals": signals.to_dict() if signals is not None else None,
        }
        emit(self.log, CHECKPOINT_DECISION, request.request_id, decision_payload)

        # 6. Block DENY decisions immediately
        if decision.decision == DENY:
            blocked_payload = {
                "decision": decision.decision,
                "evidence_id": decision.evidence_id,
                "rule_id": decision.rule_id,
                "reason": decision.reason,
                "tool": request.tool,
            }
            emit(self.log, TOOL_BLOCKED, request.request_id, blocked_payload)

            error_data = {
                "evidence_id": decision.evidence_id,
                "reason": decision.reason,
                "decision": decision.decision,
                "rule_id": decision.rule_id,
            }
            return error_response(
                effective_rpc_id,
                POLICY_DENIED,
                decision.reason,
                data=error_data,
            )

        # 7. Execute ALLOW decisions with containment
        if decision.decision == ALLOW:
            emit(
                self.log,
                TOOL_STARTED,
                request.request_id,
                {"tool": request.tool, "arguments": request.arguments, "evidence_id": decision.evidence_id},
            )

            try:
                tool_result = self.executor.execute(request.tool, request.arguments)
            except Exception as exc:
                containment_payload = {
                    "tool": request.tool,
                    "evidence_id": decision.evidence_id,
                    "error_type": type(exc).__name__,
                    "error": str(exc),
                }
                emit(self.log, TOOL_TIMEOUT, request.request_id, containment_payload)
                return error_response(
                    effective_rpc_id,
                    TOOL_FAILED,
                    f"Tool execution failed: {exc}",
                    data={"evidence_id": decision.evidence_id, "error_type": type(exc).__name__},
                )

            emit(
                self.log,
                TOOL_COMPLETED,
                request.request_id,
                {"tool": request.tool, "result": tool_result, "evidence_id": decision.evidence_id},
            )

            return success_response(
                effective_rpc_id,
                {
                    "decision": decision.decision,
                    "evidence_id": decision.evidence_id,
                    "tool_result": tool_result,
                    "result": tool_result,
                },
            )

        # Non-ALLOW non-DENY response (e.g. HOLD placeholder for now)
        return {
            "decision": decision.decision,
            "evidence_id": decision.evidence_id,
            "rule_id": decision.rule_id,
            "reason": decision.reason,
            "policy_version": decision.policy_version,
        }
