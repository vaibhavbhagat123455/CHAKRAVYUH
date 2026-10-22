"""MCP-style JSON-RPC-over-stdio proxy."""

from __future__ import annotations

import json
import hashlib
import hmac
import os
import sys
from typing import Any

from core.schemas import ToolRequest
from core.action import action_digest

from .checkpoint import Checkpoint
from .jsonrpc import JsonRpcError, RpcRequest, parse_request, success
from .tool_executor import LocalSandboxExecutor, SimulatedToolExecutor


class McpToolProxy:
    def __init__(self, checkpoint: Checkpoint | None = None, executor: SimulatedToolExecutor | None = None,
                 *, approval_secret: str | None = None) -> None:
        self.checkpoint = checkpoint or Checkpoint()
        self.executor = executor or LocalSandboxExecutor()
        self.pending: dict[str, tuple[ToolRequest, str]] = {}
        self.approval_secret = approval_secret or os.getenv("APPROVAL_BRIDGE_SECRET", "")

    def handle(self, raw: str | bytes | dict[str, Any]) -> dict[str, Any]:
        try:
            request = parse_request(raw)
            if request.method == "tools/approve":
                return self._approve(request)
            if request.method != "tools/call":
                raise JsonRpcError(-32601, "Only tools/call and tools/approve are supported", request.request_id)
            tool_request = self._tool_request(request)
            content = request.params.get("content", "")
            decision = self.checkpoint.evaluate(tool_request, content)
            if decision.decision == "DENY":
                self.checkpoint.log.append(
                    "TOOL_BLOCKED", tool_request.request_id,
                    {"reason": decision.reason, "evidence_id": decision.evidence_id},
                    scenario_id=tool_request.scenario_id, decision="DENY",
                    evidence_id=decision.evidence_id, policy_version=decision.policy_version,
                )
                return JsonRpcError(
                    -32001, "Tool call denied by checkpoint", request.request_id,
                    {"evidence_id": decision.evidence_id, "reason": decision.reason,
                     "layers": [layer.to_dict() for layer in decision.layer_results]},
                ).response()
            if decision.decision == "HOLD":
                self.pending[tool_request.request_id] = (tool_request, content)
                return success(request.request_id, self._decision_result(decision))
            start_event = self.checkpoint.log.append("TOOL_STARTED", tool_request.request_id,
                                       {"request": tool_request.to_dict()},
                                       scenario_id=tool_request.scenario_id, decision="ALLOW",
                                       evidence_id=decision.evidence_id, policy_version=decision.policy_version)
            ring_request = ToolRequest.from_dict(start_event.payload["request"])
            result = self.executor.execute(ring_request.tool, ring_request.arguments)
            self.checkpoint.log.append("TOOL_COMPLETED", tool_request.request_id, {"result": result}, scenario_id=tool_request.scenario_id)
            response = self._decision_result(decision)
            response["tool_result"] = result
            return success(request.request_id, response)
        except JsonRpcError as exc:
            return exc.response()
        except (TypeError, ValueError) as exc:
            return JsonRpcError(-32602, str(exc), self._request_id(raw)).response()

    def _approve(self, request: RpcRequest) -> dict[str, Any]:
        params = request.params
        raw_request = params.get("request")
        if not isinstance(raw_request, dict):
            raise JsonRpcError(-32602, "tools/approve requires the original request", request.request_id)
        request_id = params.get("request_id") or raw_request.get("request_id")
        approval_id = params.get("approval_id")
        token = params.get("release_token")
        if not isinstance(request_id, str) or not isinstance(approval_id, str) or not isinstance(token, str):
            raise JsonRpcError(-32602, "tools/approve requires request_id, approval_id and release_token", request.request_id)
        if not self.approval_secret:
            raise JsonRpcError(-32003, "MCP approval bridge is not configured", request.request_id)
        expected = hmac.new(self.approval_secret.encode(), f"{approval_id}:{action_digest(raw_request)}".encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(token, expected):
            raise JsonRpcError(-32003, "Invalid or expired approval proof", request.request_id,
                               {"request_id": request_id, "evidence_id": f"ev-{hashlib.sha256(token.encode()).hexdigest()[:16]}"})
        try:
            result = self.release_held(request_id, approval_verified=True)
        except (KeyError, PermissionError) as exc:
            raise JsonRpcError(-32003, str(exc), request.request_id) from exc
        return success(request.request_id, result)

    @staticmethod
    def _decision_result(decision: Any) -> dict[str, Any]:
        return {"decision": decision.decision, "evidence_id": decision.evidence_id, "reason": decision.reason,
                "layers": [layer.to_dict() for layer in decision.layer_results]}

    def release_held(self, request_id: str, approval_verified: bool = False) -> dict[str, Any]:
        if request_id not in self.pending:
            raise KeyError(f"no pending request: {request_id}")
        if not approval_verified:
            raise PermissionError("exact approval is required before releasing a held request")
        request, _content = self.pending.pop(request_id)
        decision = self.checkpoint.decisions.get(request_id)
        start_event = self.checkpoint.log.append("TOOL_STARTED", request.request_id,
                                   {"request": request.to_dict(), "approved": True},
                                   scenario_id=request.scenario_id, decision="ALLOW",
                                   evidence_id=decision.evidence_id if decision else None,
                                   policy_version=decision.policy_version if decision else None)
        ring_request = ToolRequest.from_dict(start_event.payload["request"])
        result = self.executor.execute(ring_request.tool, ring_request.arguments)
        self.checkpoint.log.append("TOOL_COMPLETED", request.request_id, {"result": result}, scenario_id=request.scenario_id)
        return {"decision": "ALLOW", "request_id": request_id,
                "evidence_id": decision.evidence_id if decision else f"ev-{request.fingerprint()[:16]}",
                "reason": "Exact approval proof accepted by MCP proxy", "tool_result": result}

    @staticmethod
    def _tool_request(rpc: RpcRequest) -> ToolRequest:
        params = rpc.params
        if isinstance(params.get("request"), dict):
            return ToolRequest.from_dict(params["request"])
        required = {"name", "arguments", "purpose", "scenario_id"}
        missing = required - params.keys()
        if missing:
            raise ValueError(f"tools/call params are missing: {sorted(missing)}")
        return ToolRequest(
            request_id=str(params.get("request_id") or f"rpc-{rpc.request_id}"),
            tool=params["name"], arguments=params["arguments"], purpose=params["purpose"], scenario_id=params["scenario_id"],
        )

    @staticmethod
    def _request_id(raw: Any) -> Any:
        return raw.get("id") if isinstance(raw, dict) else None


def main() -> None:
    proxy = McpToolProxy()
    for line in sys.stdin:
        if not line.strip():
            continue
        sys.stdout.write(json.dumps(proxy.handle(line), ensure_ascii=False, sort_keys=True) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
