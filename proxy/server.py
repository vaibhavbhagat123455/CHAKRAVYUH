"""MCP Proxy Server implementation with dependency injection and audit logging."""

from __future__ import annotations

import time
from typing import Any, Dict, Optional

from core.contracts import POLICY_VERSION
from proxy.canonical import action_digest
from proxy.checkpoint import decide, layers
from proxy.config import ProxyConfig
from proxy.events import (
    ANALYSIS_RECORDED,
    CHECKPOINT_DECISION,
    HOLD_CREATED,
    HOLD_DENIED,
    HOLD_EXPIRED,
    HOLD_RELEASED,
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
from proxy.models import ALLOW, DENY, HOLD, ApprovalResult, DecisionSignals, ToolRequest
from proxy.pending import PendingStore
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
        pending_store: Optional[PendingStore] = None,
    ) -> None:
        self.log = log
        self.analyser = analyser
        self.executor = executor
        self.approval = approval
        self.config = config if config is not None else ProxyConfig()
        self.clock = clock
        self.policy_version = POLICY_VERSION
        self.policy = get_policy(self.policy_version)
        self.pending_store = (
            pending_store
            if pending_store is not None
            else PendingStore(clock=self.clock, hold_ttl_seconds=self.config.hold_ttl_seconds)
        )

    def _execute_and_contain(
        self,
        request_id: str,
        tool: str,
        arguments: Dict[str, Any],
        evidence_id: str,
        rpc_id: Any,
    ) -> Dict[str, Any]:
        """Execute tool with timeout/failure containment and audit logging."""
        emit(self.log, TOOL_STARTED, request_id, {
            "tool": tool, "arguments": arguments, "evidence_id": evidence_id,
        })
        try:
            tool_result = self.executor.execute(tool, arguments)
        except Exception as exc:
            emit(self.log, TOOL_TIMEOUT, request_id, {
                "tool": tool, "evidence_id": evidence_id,
                "error_type": type(exc).__name__, "error": str(exc),
            })
            return error_response(
                rpc_id,
                TOOL_FAILED,
                f"Tool execution failed: {exc}",
                data={"evidence_id": evidence_id, "error_type": type(exc).__name__},
            )
        emit(self.log, TOOL_COMPLETED, request_id, {
            "tool": tool, "result": tool_result, "evidence_id": evidence_id,
        })
        return success_response(rpc_id, {
            "decision": ALLOW, "evidence_id": evidence_id,
            "tool_result": tool_result, "result": tool_result,
        })

    def handle_tool_call(
        self,
        request: ToolRequest,
        rpc_id: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """Handle incoming tool call attempt with full audit trail and guarded execution."""
        effective_rpc_id = rpc_id if rpc_id is not None else request.request_id
        emit(self.log, REQUEST_RECEIVED, request.request_id, request.to_dict())

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

        decision = decide(request, signals, policy_version=self.policy_version, policy=self.policy)

        for lr in layers(request, signals, decision, self.policy):
            emit(self.log, LAYER_EVALUATED, request.request_id, lr.to_dict())

        emit(self.log, CHECKPOINT_DECISION, request.request_id, {
            "decision": decision.decision, "evidence_id": decision.evidence_id,
            "rule_id": decision.rule_id, "reason": decision.reason,
            "policy_version": decision.policy_version,
            "signals": signals.to_dict() if signals is not None else None,
        })

        if decision.decision == DENY:
            emit(self.log, TOOL_BLOCKED, request.request_id, {
                "decision": decision.decision, "evidence_id": decision.evidence_id,
                "rule_id": decision.rule_id, "reason": decision.reason, "tool": request.tool,
            })
            return error_response(effective_rpc_id, POLICY_DENIED, decision.reason, data={
                "evidence_id": decision.evidence_id, "reason": decision.reason,
                "decision": decision.decision, "rule_id": decision.rule_id,
            })

        if decision.decision == ALLOW:
            return self._execute_and_contain(
                request.request_id, request.tool, request.arguments, decision.evidence_id, effective_rpc_id
            )

        if decision.decision == HOLD:
            approval_id = f"appr-{request.request_id}"
            if self.approval is not None:
                res = self.approval.create_approval(request)
                if isinstance(res, dict) and "approval_id" in res:
                    approval_id = res["approval_id"]
                elif isinstance(res, str):
                    approval_id = res

            record = self.pending_store.add(
                request=request, evidence_id=decision.evidence_id,
                signals=signals, approval_id=approval_id,
            )
            emit(self.log, HOLD_CREATED, request.request_id, {
                "approval_id": approval_id, "evidence_id": decision.evidence_id,
                "action_digest": record.action_digest, "tool": request.tool,
            })
            return {
                "decision": HOLD, "evidence_id": decision.evidence_id,
                "approval_id": approval_id,
            }

        return {
            "decision": decision.decision, "evidence_id": decision.evidence_id,
            "rule_id": decision.rule_id, "reason": decision.reason,
            "policy_version": decision.policy_version,
        }

    def release_pending(
        self,
        request_id: str,
        approval_result: ApprovalResult,
    ) -> Dict[str, Any]:
        """Verify authorization and release a held request for execution."""
        record = self.pending_store.get(request_id)
        if record is None:
            emit(self.log, HOLD_DENIED, request_id, {
                "outcome": "denied", "reason": "Unknown pending request",
            })
            return error_response(request_id, POLICY_DENIED, "Unknown pending request")

        now = self.clock.now() if self.clock is not None else time.time()
        if now > record.expires_at:
            self.pending_store.remove(request_id)
            emit(self.log, HOLD_EXPIRED, request_id, {
                "outcome": "expired", "evidence_id": record.evidence_id,
                "reason": "Pending request expired",
            })
            return error_response(request_id, POLICY_DENIED, "Pending request expired")

        computed_digest = action_digest(record.request.tool, record.request.arguments)
        if not approval_result.approved or approval_result.action_digest != computed_digest:
            self.pending_store.remove(request_id)
            emit(self.log, HOLD_DENIED, request_id, {
                "outcome": "denied", "evidence_id": record.evidence_id,
                "reason": "Approval verification failed or denied",
            })
            return error_response(request_id, POLICY_DENIED, "Approval verification failed or denied")

        decision = decide(record.request, record.signals, policy_version=self.policy_version, policy=self.policy)
        if decision.decision == DENY:
            self.pending_store.remove(request_id)
            emit(self.log, HOLD_DENIED, request_id, {
                "outcome": "denied", "evidence_id": decision.evidence_id,
                "reason": decision.reason,
            })
            return error_response(request_id, POLICY_DENIED, decision.reason, data={"evidence_id": decision.evidence_id})

        emit(self.log, HOLD_RELEASED, request_id, {
            "approval_id": approval_result.approval_id,
            "evidence_id": record.evidence_id,
            "action_digest": record.action_digest,
        })
        self.pending_store.remove(request_id)
        return self._execute_and_contain(
            request_id=request_id,
            tool=record.request.tool,
            arguments=record.request.arguments,
            evidence_id=record.evidence_id,
            rpc_id=request_id,
        )
