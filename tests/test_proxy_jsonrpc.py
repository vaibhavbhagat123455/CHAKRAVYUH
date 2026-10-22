"""Tests for proxy JSON-RPC 2.0 protocol layer."""

import unittest

from proxy.jsonrpc import (
    INTERNAL_ERROR,
    INVALID_PARAMS,
    INVALID_REQUEST,
    METHOD_NOT_FOUND,
    PARSE_ERROR,
    POLICY_DENIED,
    TOOL_FAILED,
    RpcError,
    error_response,
    success_response,
)


class TestJsonRpcBuildersAndConstants(unittest.TestCase):
    """Test constants, success_response, error_response, and RpcError."""

    def test_constants_match_spec(self) -> None:
        self.assertEqual(PARSE_ERROR, -32700)
        self.assertEqual(INVALID_REQUEST, -32600)
        self.assertEqual(METHOD_NOT_FOUND, -32601)
        self.assertEqual(INVALID_PARAMS, -32602)
        self.assertEqual(INTERNAL_ERROR, -32603)
        self.assertEqual(POLICY_DENIED, -32003)
        self.assertEqual(TOOL_FAILED, -32004)

    def test_success_response_structure(self) -> None:
        resp = success_response("req-1", {"status": "ok"})
        self.assertEqual(
            resp,
            {
                "jsonrpc": "2.0",
                "id": "req-1",
                "result": {"status": "ok"},
            },
        )
        # Even with None or integer id
        resp2 = success_response(123, [1, 2, 3])
        self.assertEqual(resp2["jsonrpc"], "2.0")
        self.assertEqual(resp2["id"], 123)
        self.assertEqual(resp2["result"], [1, 2, 3])

    def test_error_response_without_data(self) -> None:
        resp = error_response("req-2", METHOD_NOT_FOUND, "Method not found")
        self.assertEqual(
            resp,
            {
                "jsonrpc": "2.0",
                "id": "req-2",
                "error": {
                    "code": -32601,
                    "message": "Method not found",
                },
            },
        )

    def test_error_response_with_data(self) -> None:
        data = {"evidence_id": "ev-123", "decision": "DENY"}
        resp = error_response("req-3", POLICY_DENIED, "Policy denied", data=data)
        self.assertEqual(
            resp,
            {
                "jsonrpc": "2.0",
                "id": "req-3",
                "error": {
                    "code": -32003,
                    "message": "Policy denied",
                    "data": data,
                },
            },
        )

    def test_rpc_error_exception(self) -> None:
        err = RpcError(code=PARSE_ERROR, message="Parse error", data={"raw": "abc"}, rpc_id=None)
        self.assertEqual(err.code, -32700)
        self.assertEqual(err.message, "Parse error")
        self.assertEqual(err.data, {"raw": "abc"})
        self.assertIsNone(err.rpc_id)
        self.assertIsInstance(err, Exception)


if __name__ == "__main__":
    unittest.main()
