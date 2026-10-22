"""MCP-style JSON-RPC-over-stdio proxy."""

from __future__ import annotations

import json
import sys
from typing import Any

from core.schemas import ToolRequest

from .checkpoint import Checkpoint
from .jsonrpc import JsonRpcError, RpcRequest, parse_request, success
from .tool_executor import SimulatedToolExecutor


class McpToolProxy:
    def __init__(self, checkpoint: Checkpoint | None = None, executor: SimulatedToolExecutor | None = None) -> None:
        self.checkpoint = checkpoint or Checkpoint()
        self.executor = executor or SimulatedToolExecutor()
        self.pending: dict[str, tuple[ToolRequest, str]] = {}

    def handle(self, raw: str | bytes | dict[str, Any]) -> dict[str, Any]:
        try:
            request = parse_request(raw)
            if request.method != "tools/call":
                raise JsonRpcError(-32601, "Only tools/call is supported", request.request_id)
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
                    {"evidence_id": decision.evidence_id, "reason": decision.reason},
                ).response()
            if decision.decision == "HOLD":
                self.pending[tool_request.request_id] = (tool_request, content)
                return success(request.request_id, {"decision": "HOLD", "evidence_id": decision.evidence_id, "reason": decision.reason})
            result = self.executor.execute(tool_request.tool, tool_request.arguments)
            self.checkpoint.log.append("TOOL_COMPLETED", tool_request.request_id, {"result": result}, scenario_id=tool_request.scenario_id)
            return success(request.request_id, {"decision": "ALLOW", "evidence_id": decision.evidence_id, "tool_result": result})
        except JsonRpcError as exc:
            return exc.response()
        except (TypeError, ValueError) as exc:
            return JsonRpcError(-32602, str(exc), self._request_id(raw)).response()

    def release_held(self, request_id: str, approval_verified: bool = False) -> dict[str, Any]:
        if request_id not in self.pending:
            raise KeyError(f"no pending request: {request_id}")
        if not approval_verified:
            raise PermissionError("exact approval is required before releasing a held request")
        request, _content = self.pending.pop(request_id)
        result = self.executor.execute(request.tool, request.arguments)
        self.checkpoint.log.append("TOOL_COMPLETED", request.request_id, {"result": result}, scenario_id=request.scenario_id)
        return {"decision": "ALLOW", "request_id": request_id, "tool_result": result}

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
