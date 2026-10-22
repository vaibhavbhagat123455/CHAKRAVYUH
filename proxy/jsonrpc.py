"""JSON-RPC 2.0 protocol definitions and utilities."""

from __future__ import annotations

import json
from typing import Any, Dict, Optional, Tuple

from proxy.models import ToolRequest

# Standard JSON-RPC 2.0 and Chakravyuh error codes
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
METHOD_NOT_FOUND = -32601
INVALID_PARAMS = -32602
INTERNAL_ERROR = -32603
POLICY_DENIED = -32003
TOOL_FAILED = -32004

# Only tools/call is supported at this gateway boundary
SUPPORTED_METHODS = frozenset({"tools/call"})

_TOOL_CALL_PARAM_KEYS = frozenset({
    "request_id",
    "tool",
    "arguments",
    "purpose",
    "scenario_id",
})


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


def validate_method(method: str, rpc_id: Optional[Any] = None) -> None:
    """Validate that the method is in SUPPORTED_METHODS.

    Raises RpcError(METHOD_NOT_FOUND) if method is unsupported.
    """
    if method not in SUPPORTED_METHODS:
        raise RpcError(
            METHOD_NOT_FOUND,
            f"Method '{method}' not found. Supported methods: {sorted(SUPPORTED_METHODS)}",
            rpc_id=rpc_id,
        )


def validate_tool_call_params(params: Any, rpc_id: Optional[Any] = None) -> None:
    """Validate tool-call params.

    Requires params to be an object with keys exactly matching:
    request_id, tool, arguments, purpose, scenario_id.
    arguments must be an object (dict).
    Raises RpcError(INVALID_PARAMS) on any violation.
    """
    if not isinstance(params, dict):
        raise RpcError(INVALID_PARAMS, "params must be an object", rpc_id=rpc_id)

    # Missing keys
    for key in ("request_id", "tool", "arguments", "purpose", "scenario_id"):
        if key not in params:
            raise RpcError(
                INVALID_PARAMS,
                f"Missing required parameter '{key}' in params",
                rpc_id=rpc_id,
            )

    # Unknown keys
    unknown = set(params.keys()) - _TOOL_CALL_PARAM_KEYS
    if unknown:
        raise RpcError(
            INVALID_PARAMS,
            f"Unknown parameter(s) in params: {sorted(unknown)}",
            rpc_id=rpc_id,
        )

    # arguments must be an object
    args = params["arguments"]
    if not isinstance(args, dict):
        raise RpcError(
            INVALID_PARAMS,
            f"Parameter 'arguments' must be an object (dict), got: {type(args).__name__}",
            rpc_id=rpc_id,
        )


def validate_request(raw: Any) -> Tuple[Any, ToolRequest]:
    """Validate JSON-RPC 2.0 tool-call request and construct a ToolRequest.

    Validates envelope, method, and tool-call params.
    Converts params into ToolRequest using ToolRequest.from_dict.
    Catches ValueError from ToolRequest and re-raises as RpcError(INVALID_PARAMS).
    Returns (rpc_id, ToolRequest).
    """
    validate_envelope(raw)
    rpc_id = raw["id"]
    validate_method(raw["method"], rpc_id=rpc_id)
    params = raw.get("params")
    validate_tool_call_params(params, rpc_id=rpc_id)
    try:
        req = ToolRequest.from_dict(params)
    except ValueError as exc:
        raise RpcError(INVALID_PARAMS, str(exc), rpc_id=rpc_id) from exc
    return rpc_id, req

