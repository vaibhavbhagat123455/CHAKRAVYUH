"""JSON-RPC 2.0 protocol definitions and utilities."""

from __future__ import annotations

import json
from typing import Any, Dict, Optional

# Standard JSON-RPC 2.0 and Chakravyuh error codes
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603
POLICY_DENIED = -32003
TOOL_FAILED = -32004


class RpcError(Exception):
    """Exception carrying JSON-RPC error fields."""

    def __init__(
        self,
        code: int,
        message: str,
        data: Optional[Any] = None,
        rpc_id: Optional[Any] = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data
        self.rpc_id = rpc_id

    def to_dict(self) -> Dict[str, Any]:
        """Convert error to JSON-RPC error response dict."""
        return error_response(self.rpc_id, self.code, self.message, self.data)


def success_response(rpc_id: Any, result: Any) -> Dict[str, Any]:
    """Build standard JSON-RPC 2.0 success response dictionary."""
    return {
        "jsonrpc": "2.0",
        "id": rpc_id,
        "result": result,
    }


def error_response(
    rpc_id: Any,
    code: int,
    message: str,
    data: Optional[Any] = None,
) -> Dict[str, Any]:
    """Build standard JSON-RPC 2.0 error response dictionary."""
    err: Dict[str, Any] = {
        "code": code,
        "message": message,
    }
    if data is not None:
        err["data"] = data
    return {
        "jsonrpc": "2.0",
        "id": rpc_id,
        "error": err,
    }


def parse_request(line: str) -> Dict[str, Any]:
    """Parse a single JSON-RPC line into a dictionary.

    Raises RpcError(PARSE_ERROR) on blank lines, decode errors, or non-object payloads.
    """
    clean_line = line.strip()
    if not clean_line:
        raise RpcError(PARSE_ERROR, "Empty or blank request line", rpc_id=None)

    try:
        parsed = json.loads(clean_line)
    except json.JSONDecodeError as exc:
        raise RpcError(PARSE_ERROR, f"Parse error: {exc}", rpc_id=None) from exc

    if not isinstance(parsed, dict):
        raise RpcError(PARSE_ERROR, "Invalid JSON-RPC payload: expected JSON object", rpc_id=None)

    return parsed


def validate_envelope(raw: Any) -> None:
    """Validate JSON-RPC 2.0 framing.

    Requires jsonrpc == '2.0', an 'id' key present, and a string 'method'.
    Echoes the id in RpcError if it can be read, otherwise None.
    """
    rpc_id: Optional[Any] = None
    if isinstance(raw, dict) and "id" in raw:
        rpc_id = raw["id"]

    if not isinstance(raw, dict):
        raise RpcError(INVALID_REQUEST, "Invalid Request: expected object", rpc_id=None)

    if raw.get("jsonrpc") != "2.0":
        raise RpcError(INVALID_REQUEST, "Invalid Request: 'jsonrpc' must be '2.0'", rpc_id=rpc_id)

    if "id" not in raw:
        raise RpcError(INVALID_REQUEST, "Invalid Request: missing 'id'", rpc_id=None)

    method = raw.get("method")
    if not isinstance(method, str):
        raise RpcError(INVALID_REQUEST, "Invalid Request: 'method' must be a string", rpc_id=rpc_id)
