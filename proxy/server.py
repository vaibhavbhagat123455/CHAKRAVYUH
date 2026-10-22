"""MCP Proxy Server implementation with dependency injection, audit logging, and stdio loop."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional, TextIO

from core.contracts import POLICY_VERSION, validate_event_type
from proxy.adapters import CallableAnalyser, CallableApproval, CallableLogWriter, load_callable
from proxy.canonical import action_digest
from proxy.checkpoint import decide, layers
from proxy.config import ProxyConfig
from proxy.events import (
    ANALYSIS_RECORDED, CHECKPOINT_DECISION, HOLD_CREATED, HOLD_DENIED, HOLD_EXPIRED,
    HOLD_RELEASED, LAYER_EVALUATED, REQUEST_RECEIVED, TOOL_BLOCKED, TOOL_COMPLETED, TOOL_STARTED, TOOL_TIMEOUT, emit,
)
from proxy.executor import SimulatedExecutor
from proxy.interfaces import Analyser, ApprovalService, Clock, LogWriter, ToolExecutor
from proxy.jsonrpc import INTERNAL_ERROR, POLICY_DENIED, TOOL_FAILED, RpcError, error_response, parse_request, success_response, validate_request
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


class _NoOpAnalyser(Analyser):
    def analyse_tool_call(self, tool_call: Dict[str, Any], original_goal: str) -> Optional[Dict[str, Any]]:
        return None


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
        self.approval, self.clock, self.policy_version = approval, clock, POLICY_VERSION
        self.config = config if config is not None else ProxyConfig()
        self.policy = policy if policy is not None else get_policy(self.policy_version)
        self.pending_store = pending_store or PendingStore(clock=clock, hold_ttl_seconds=self.config.hold_ttl_seconds)

    def _execute_and_contain(self, req_id: str, tool: str, args: Dict[str, Any], ev_id: str, rpc_id: Any, auth_token: Optional[Any] = None) -> Dict[str, Any]:
        emit(self.log, TOOL_STARTED, req_id, {"tool": tool, "arguments": args, "evidence_id": ev_id})
        try:
            res = self.executor.execute(tool, args, auth_token=auth_token, request_id=req_id)
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
            if raw is not None:
                clean = {k: v for k, v in raw.items() if k != "model_version"}
                signals = DecisionSignals.from_dict(clean)
                analysis_payload["signals"] = signals.to_dict()
                if "model_version" in raw: analysis_payload["model_version"] = raw["model_version"]
            else:
                signals, analysis_payload["signals"] = None, None
        except Exception as exc:
            analysis_payload.update({"analyser_failed": True, "signals": None, "error_type": type(exc).__name__})
        emit(self.log, ANALYSIS_RECORDED, request.request_id, analysis_payload)

        decision = decide(request, signals, policy_version=self.policy_version, policy=self.policy)
        for lr in layers(request, signals, decision, self.policy):
            emit(self.log, LAYER_EVALUATED, request.request_id, lr.to_dict())
        emit(self.log, CHECKPOINT_DECISION, request.request_id, {
            "decision": decision.decision, "evidence_id": decision.evidence_id, "rule_id": decision.rule_id,
            "reason": decision.reason, "policy_version": decision.policy_version, "signals": signals.to_dict() if signals is not None else None,
        })

        if decision.decision == DENY:
            emit(self.log, TOOL_BLOCKED, request.request_id, {"decision": DENY, "evidence_id": decision.evidence_id, "rule_id": decision.rule_id, "reason": decision.reason, "tool": request.tool})
            return error_response(eff_id, POLICY_DENIED, decision.reason, data={"evidence_id": decision.evidence_id, "reason": decision.reason, "decision": DENY, "rule_id": decision.rule_id})
        if decision.decision == ALLOW:
            return self._execute_and_contain(request.request_id, request.tool, request.arguments, decision.evidence_id, eff_id, auth_token=decision)
        if decision.decision == HOLD:
            appr_id = f"appr-{request.request_id}"
            if self.approval is not None:
                res = self.approval.create_approval(request)
                appr_id = res.get("approval_id", appr_id) if isinstance(res, dict) else str(res)
            rec = self.pending_store.add(request, decision.evidence_id, signals, appr_id)
            emit(self.log, HOLD_CREATED, request.request_id, {"approval_id": appr_id, "evidence_id": decision.evidence_id, "action_digest": rec.action_digest, "tool": request.tool})
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
        return self._execute_and_contain(request_id, record.request.tool, record.request.arguments, record.evidence_id, request_id, auth_token=record)

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
    return ProxyServer(
        log=log if log is not None else _MemoryLog(),
        analyser=analyser if analyser is not None else _DefaultAnalyser(),
        executor=executor if executor is not None else SimulatedExecutor(timeout_seconds=cfg.tool_timeout_seconds),
        approval=approval, config=cfg, clock=clock,
        policy=policy if policy is not None else (load_policy(cfg.policy_file) if cfg.policy_file else None),
    )


def build_server_from_config(config: ProxyConfig, analyser: Optional[Analyser] = None, stderr: Optional[TextIO] = None) -> ProxyServer:
    """Build a ProxyServer using configured targets or announce fallback notices."""
    err = stderr or sys.stderr
    log = None
    if config.log_target:
        raw_l = load_callable(config.log_target)
        log = raw_l() if isinstance(raw_l, type) and hasattr(raw_l, "append_event") else CallableLogWriter(raw_l)
    if log is None: print("Notice: Falling back to in-memory log", file=err)

    if analyser is None:
        if config.analyser_target:
            raw_a = load_callable(config.analyser_target)
            analyser = raw_a() if isinstance(raw_a, type) and hasattr(raw_a, "analyse_tool_call") else CallableAnalyser(raw_a)
        else:
            print("Notice: Falling back to no-op analyser", file=err)
            analyser = _NoOpAnalyser()

    approval = CallableApproval(load_callable(config.approval_create_target), load_callable(config.approval_verify_target)) if (config.approval_create_target and config.approval_verify_target) else None
    return build_server(log=log, analyser=analyser, approval=approval, config=config)


def _parse_cli_args(argv: List[str]) -> tuple[ProxyConfig, Optional[Analyser]]:
    parser = argparse.ArgumentParser(description="AI Chakravyuh MCP Proxy Server")
    for f in ("--tool-timeout", "--hold-ttl", "--policy-file", "--analyser-fixture", "--log", "--analyser", "--approval-create", "--approval-verify"):
        parser.add_argument(f, type=float if f == "--tool-timeout" else (int if f == "--hold-ttl" else str), default=None)
    args = parser.parse_args(argv)
    base = ProxyConfig.from_env()
    cfg = ProxyConfig(
        tool_timeout_seconds=args.tool_timeout or base.tool_timeout_seconds,
        hold_ttl_seconds=args.hold_ttl or base.hold_ttl_seconds,
        policy_file=args.policy_file or base.policy_file,
        log_target=args.log or base.log_target,
        analyser_target=args.analyser or base.analyser_target,
        approval_create_target=args.approval_create or base.approval_create_target,
        approval_verify_target=args.approval_verify or base.approval_verify_target,
    )
    analyser = None
    if args.analyser_fixture:
        raw = args.analyser_fixture.strip()
        data = json.load(open(raw, "r", encoding="utf-8")) if os.path.exists(raw) else json.loads(raw)
        analyser = _FixtureAnalyser(data)
    return cfg, analyser


def main(argv: Optional[List[str]] = None, stdin: Optional[TextIO] = None, stdout: Optional[TextIO] = None, stderr: Optional[TextIO] = None) -> int:
    """CLI entry point for running proxy server over stdio."""
    args_list = argv if argv is not None else sys.argv[1:]
    in_s, out_s, err_s = stdin or sys.stdin, stdout or sys.stdout, stderr or sys.stderr

    try:
        cfg, analyser = _parse_cli_args(args_list)
    except Exception as exc:
        print(f"CLI configuration error: {exc}", file=err_s)
        return 1

    server = build_server_from_config(cfg, analyser=analyser, stderr=err_s)
    for line in in_s:
        try:
            raw = parse_request(line)
            rpc_id, req = validate_request(raw)
            resp = server.handle_tool_call(req, rpc_id=rpc_id)
        except RpcError as err:
            print(f"RPC error: {err}", file=err_s); resp = err.to_dict()
        except Exception as exc:
            print(f"Internal error: {exc}", file=err_s); resp = error_response(None, INTERNAL_ERROR, str(exc))

        if isinstance(resp, dict) and "jsonrpc" not in resp:
            resp = success_response(rpc_id, resp)
        out_s.write(json.dumps(resp) + "\n")
        out_s.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
