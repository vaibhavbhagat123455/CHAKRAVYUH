"""JSON-RPC 2.0 protocol definitions and utilities."""

from __future__ import annotations

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
