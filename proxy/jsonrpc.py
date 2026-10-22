"""Small JSON-RPC 2.0 codec for MCP stdio messages."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping


class JsonRpcError(ValueError):
    def __init__(self, code: int, message: str, request_id: Any = None, data: Any = None):
        super().__init__(message)
        self.code, self.message, self.request_id, self.data = code, message, request_id, data

    def response(self) -> dict[str, Any]:
        error: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.data is not None:
            error["data"] = self.data
        return {"jsonrpc": "2.0", "id": self.request_id, "error": error}


@dataclass(frozen=True)
class RpcRequest:
    request_id: Any
    method: str
    params: dict[str, Any]


def parse_request(raw: str | bytes | Mapping[str, Any]) -> RpcRequest:
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise JsonRpcError(-32700, "Parse error") from exc
    if not isinstance(raw, Mapping):
        raise JsonRpcError(-32600, "Invalid Request")
    if raw.get("jsonrpc") != "2.0":
        raise JsonRpcError(-32600, "jsonrpc must be '2.0'", raw.get("id"))
    if "id" not in raw:
        raise JsonRpcError(-32600, "Tool calls must have an id")
    method = raw.get("method")
    if not isinstance(method, str) or not method:
        raise JsonRpcError(-32600, "method must be a non-empty string", raw.get("id"))
    params = raw.get("params", {})
    if not isinstance(params, dict):
        raise JsonRpcError(-32602, "params must be an object", raw.get("id"))
    return RpcRequest(raw["id"], method, dict(params))


def success(request_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}
