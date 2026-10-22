"""MCP Proxy Server implementation with dependency injection, audit logging, and stdio loop."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional, TextIO

from core.contracts import POLICY_VERSION, validate_event_type
from proxy.canonical import action_digest
from proxy.checkpoint import decide, layers
from proxy.config import ProxyConfig
from proxy.events import (
    ANALYSIS_RECORDED, CHECKPOINT_DECISION, HOLD_CREATED, HOLD_DENIED,
    HOLD_EXPIRED, HOLD_RELEASED, LAYER_EVALUATED, REQUEST_RECEIVED,
    TOOL_BLOCKED, TOOL_COMPLETED, TOOL_STARTED, TOOL_TIMEOUT, emit,
)
from proxy.executor import SimulatedExecutor
from proxy.interfaces import Analyser, ApprovalService, Clock, LogWriter, ToolExecutor
from proxy.jsonrpc import (
    INTERNAL_ERROR, POLICY_DENIED, TOOL_FAILED, RpcError,
    error_response, parse_request, success_response, validate_request,
)
from proxy.models import ALLOW, DENY, HOLD, ApprovalResult, DecisionSignals, ToolRequest
from proxy.pending import PendingRecord, PendingStore
from proxy.policy import PolicyConfig, get_policy, load_policy


class _MemoryLog(LogWriter):
    def __init__(self) -> None: self.events: List[Dict[str, Any]] = []
    def append_event(self, event_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        validate_event_type(event_type)
        env = {"event_type": event_type, "payload": dict(payload)}
        self.events.append(env)
        return env


class _DefaultAnalyser(Analyser):
    def analyse_tool_call(self, tool_call: Dict[str, Any], original_goal: str) -> Dict[str, Any]:
        return {"prompt_injection": False, "goal_drift": False, "sensitive_data_risk": "low", "risk_score": 0.05, "recommended_action": "ALLOW", "reason": "Default analyser"}


class _FixtureAnalyser(Analyser):
    def __init__(self, fixtures: Dict[str, Any]) -> None: self.fixtures = fixtures
    def analyse_tool_call(self, tool_call: Dict[str, Any], original_goal: str) -> Dict[str, Any]:
        req_id = tool_call.get("request_id")
        if req_id and req_id in self.fixtures: return self.fixtures[req_id]
        return {"prompt_injection": False, "goal_drift": False, "sensitive_data_risk": "low", "risk_score": 0.05, "recommended_action": "ALLOW", "reason": "Fixture fallback"}


class ProxyServer:
    """Core MCP security proxy server intercepting and governing tool calls."""

    def __init__(
        self, log: LogWriter, analyser: Analyser, executor: ToolExecutor,
        approval: Optional[ApprovalService] = None, config: Optional[ProxyConfig] = None,
        clock: Optional[Clock] = None, pending_store: Optional[PendingStore] = None, policy: Optional[PolicyConfig] = None,
    ) -> None:
        self.log, self.analyser, self.executor = log, analyser, executor
        self.approval, self.clock = approval, clock
        self.config = config if config is not None else ProxyConfig()
        self.policy_version = POLICY_VERSION
        self.policy = policy if policy is not None else get_policy(self.policy_version)
        self.pending_store = pending_store or PendingStore(clock=clock, hold_ttl_seconds=self.config.hold_ttl_seconds)

    def _execute_and_contain(self, req_id: str, tool: str, args: Dict[str, Any], ev_id: str, rpc_id: Any) -> Dict[str, Any]:
        emit(self.log, TOOL_STARTED, req_id, {"tool": tool, "arguments": args, "evidence_id": ev_id})
        try:
            res = self.executor.execute(tool, args)
            emit(self.log, TOOL_COMPLETED, req_id, {"tool": tool, "result": res, "evidence_id": ev_id})
            return success_response(rpc_id, {"decision": ALLOW, "evidence_id": ev_id, "tool_result": res, "result": res})
        except Exception as exc:
            emit(self.log, TOOL_TIMEOUT, req_id, {"tool": tool, "evidence_id": ev_id, "error_type": type(exc).__name__, "error": str(exc)})
            return error_response(rpc_id, TOOL_FAILED, f"Tool execution failed: {exc}", data={"evidence_id": ev_id, "error_type": type(exc).__name__})

    def handle_tool_call(self, request: ToolRequest, rpc_id: Optional[Any] = None) -> Dict[str, Any]:
        eff_id = rpc_id if rpc_id is not None else request.request_id
        emit(self.log, REQUEST_RECEIVED, request.request_id, request.to_dict())

        signals: Optional[DecisionSignals] = None
        analysis_payload: Dict[str, Any] = {"analyser_failed": False}
        try:
            raw = self.analyser.analyse_tool_call(request.to_dict(), request.purpose)
            if not isinstance(raw, dict): raise ValueError("Expected dict")
            clean = {k: v for k, v in raw.items() if k != "model_version"}
            signals = DecisionSignals.from_dict(clean)
            analysis_payload["signals"] = signals.to_dict()
            if "model_version" in raw: analysis_payload["model_version"] = raw["model_version"]
        except Exception as exc:
            analysis_payload.update({"analyser_failed": True, "signals": None, "error_type": type(exc).__name__})
        emit(self.log, ANALYSIS_RECORDED, request.request_id, analysis_payload)

        decision = decide(request, signals, policy_version=self.policy_version, policy=self.policy)
        for lr in layers(request, signals, decision, self.policy):
            emit(self.log, LAYER_EVALUATED, request.request_id, lr.to_dict())
        emit(self.log, CHECKPOINT_DECISION, request.request_id, {
            "decision": decision.decision, "evidence_id": decision.evidence_id,
            "rule_id": decision.rule_id, "reason": decision.reason, "policy_version": decision.policy_version,
            "signals": signals.to_dict() if signals is not None else None,
        })

        if decision.decision == DENY:
            emit(self.log, TOOL_BLOCKED, request.request_id, {
                "decision": decision.decision, "evidence_id": decision.evidence_id,
                "rule_id": decision.rule_id, "reason": decision.reason, "tool": request.tool,
            })
            return error_response(eff_id, POLICY_DENIED, decision.reason, data={
                "evidence_id": decision.evidence_id, "reason": decision.reason,
                "decision": decision.decision, "rule_id": decision.rule_id,
            })
        if decision.decision == ALLOW:
            return self._execute_and_contain(request.request_id, request.tool, request.arguments, decision.evidence_id, eff_id)
        if decision.decision == HOLD:
            appr_id = f"appr-{request.request_id}"
            if self.approval is not None:
                res = self.approval.create_approval(request)
                appr_id = res.get("approval_id", appr_id) if isinstance(res, dict) else str(res)
            rec = self.pending_store.add(request, decision.evidence_id, signals, appr_id)
            emit(self.log, HOLD_CREATED, request.request_id, {
                "approval_id": appr_id, "evidence_id": decision.evidence_id,
                "action_digest": rec.action_digest, "tool": request.tool,
            })
            return {"decision": HOLD, "evidence_id": decision.evidence_id, "approval_id": appr_id}
        return {"decision": decision.decision, "evidence_id": decision.evidence_id, "rule_id": decision.rule_id, "reason": decision.reason, "policy_version": decision.policy_version}

    def release_pending(self, request_id: str, approval_result: ApprovalResult) -> Dict[str, Any]:
        record = self.pending_store.get(request_id)
        if record is None:
            emit(self.log, HOLD_DENIED, request_id, {"outcome": "denied", "reason": "Unknown pending request"})
            return error_response(request_id, POLICY_DENIED, "Unknown pending request")
        now = self.clock.now() if self.clock is not None else time.time()
        if now > record.expires_at:
            self.expire_pending(request_id)
            return error_response(request_id, POLICY_DENIED, "Pending request expired")
        computed = action_digest(record.request.tool, record.request.arguments)
        if not approval_result.approved or approval_result.action_digest != computed:
            self.pending_store.remove(request_id)
            emit(self.log, HOLD_DENIED, request_id, {"outcome": "denied", "evidence_id": record.evidence_id, "reason": "Approval verification failed or denied"})
            return error_response(request_id, POLICY_DENIED, "Approval verification failed or denied")
        decision = decide(record.request, record.signals, policy_version=self.policy_version, policy=self.policy)
        if decision.decision == DENY:
            self.pending_store.remove(request_id)
            emit(self.log, HOLD_DENIED, request_id, {"outcome": "denied", "evidence_id": decision.evidence_id, "reason": decision.reason})
            return error_response(request_id, POLICY_DENIED, decision.reason, data={"evidence_id": decision.evidence_id})
        emit(self.log, HOLD_RELEASED, request_id, {"approval_id": approval_result.approval_id, "evidence_id": record.evidence_id, "action_digest": record.action_digest})
        self.pending_store.remove(request_id)
        return self._execute_and_contain(request_id, record.request.tool, record.request.arguments, record.evidence_id, request_id)

    def expire_pending(self, request_id: str) -> Optional[PendingRecord]:
        record = self.pending_store.remove(request_id)
        if record is None: return None
        emit(self.log, HOLD_EXPIRED, request_id, {"outcome": "expired", "evidence_id": record.evidence_id, "reason": "Pending request expired", "tool": record.request.tool})
        return record

    def expire_due(self) -> List[PendingRecord]:
        now = self.clock.now() if self.clock is not None else time.time()
        return [self.expire_pending(r.request.request_id) for r in self.pending_store.list_all() if now >= r.expires_at and self.pending_store.get(r.request.request_id)]


def build_server(
    log: Optional[LogWriter] = None, analyser: Optional[Analyser] = None,
    executor: Optional[ToolExecutor] = None, approval: Optional[ApprovalService] = None,
    config: Optional[ProxyConfig] = None, clock: Optional[Clock] = None, policy: Optional[PolicyConfig] = None,
) -> ProxyServer:
    """Factory creating a fully configured ProxyServer instance."""
    cfg = config if config is not None else ProxyConfig.from_env()
    l = log if log is not None else _MemoryLog()
    e = executor if executor is not None else SimulatedExecutor(timeout_seconds=cfg.tool_timeout_seconds)
    a = analyser if analyser is not None else _DefaultAnalyser()
    pol = policy if policy is not None else (load_policy(cfg.policy_file) if cfg.policy_file else None)
    return ProxyServer(log=l, analyser=a, executor=e, approval=approval, config=cfg, clock=clock, policy=pol)


def _parse_cli_args(argv: List[str]) -> tuple[ProxyConfig, Optional[Analyser], Optional[PolicyConfig]]:
    parser = argparse.ArgumentParser(description="AI Chakravyuh MCP Proxy Server")
    parser.add_argument("--tool-timeout", type=float, default=None)
    parser.add_argument("--hold-ttl", type=int, default=None)
    parser.add_argument("--policy-file", type=str, default=None)
    parser.add_argument("--analyser-fixture", type=str, default=None)
    args = parser.parse_args(argv)

    base = ProxyConfig.from_env()
    cfg = ProxyConfig(
        tool_timeout_seconds=args.tool_timeout if args.tool_timeout is not None else base.tool_timeout_seconds,
        hold_ttl_seconds=args.hold_ttl if args.hold_ttl is not None else base.hold_ttl_seconds,
        policy_file=args.policy_file if args.policy_file is not None else base.policy_file,
    )
    pol = load_policy(cfg.policy_file) if cfg.policy_file else None
    analyser: Optional[Analyser] = None
    if args.analyser_fixture:
        raw_fix = args.analyser_fixture.strip()
        data = json.load(open(raw_fix, "r", encoding="utf-8")) if os.path.exists(raw_fix) else json.loads(raw_fix)
        analyser = _FixtureAnalyser(data)
    return cfg, analyser, pol


def main(argv: Optional[List[str]] = None, stdin: Optional[TextIO] = None, stdout: Optional[TextIO] = None, stderr: Optional[TextIO] = None) -> int:
    """CLI entry point for running proxy server over stdio."""
    args_list = argv if argv is not None else sys.argv[1:]
    in_s, out_s, err_s = stdin or sys.stdin, stdout or sys.stdout, stderr or sys.stderr

    try:
        cfg, analyser, pol = _parse_cli_args(args_list)
    except Exception as exc:
        print(f"CLI configuration error: {exc}", file=err_s)
        return 1

    server = build_server(config=cfg, analyser=analyser, policy=pol)
    for line in in_s:
        try:
            raw = parse_request(line)
            rpc_id, req = validate_request(raw)
            resp = server.handle_tool_call(req, rpc_id=rpc_id)
        except RpcError as err:
            print(f"RPC error: {err}", file=err_s)
            resp = err.to_dict()
        except Exception as exc:
            print(f"Internal error: {exc}", file=err_s)
            resp = error_response(None, INTERNAL_ERROR, str(exc))

        out_s.write(json.dumps(resp) + "\n")
        out_s.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
