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
    parse_request,
    success_response,
    validate_envelope,
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


class TestJsonRpcParsingAndEnvelope(unittest.TestCase):
    """Test line parsing and JSON-RPC 2.0 envelope validation."""

    def test_parse_valid_line(self) -> None:
        raw = parse_request('{"jsonrpc": "2.0", "id": 1, "method": "tools/call"}\n')
        self.assertEqual(raw, {"jsonrpc": "2.0", "id": 1, "method": "tools/call"})

    def test_parse_empty_or_blank_line_raises_parse_error(self) -> None:
        for bad_line in ("", "   ", "\t\n", "  \r\n"):
            with self.assertRaises(RpcError) as ctx:
                parse_request(bad_line)
            self.assertEqual(ctx.exception.code, PARSE_ERROR)
            self.assertIsNone(ctx.exception.rpc_id)

    def test_parse_malformed_json_raises_parse_error(self) -> None:
        for bad_json in ("{", "{key: 1}", "not-json"):
            with self.assertRaises(RpcError) as ctx:
                parse_request(bad_json)
            self.assertEqual(ctx.exception.code, PARSE_ERROR)
            self.assertIsNone(ctx.exception.rpc_id)

    def test_parse_non_object_json_raises_parse_error(self) -> None:
        for non_obj in ("[1, 2]", '"string"', "42", "true", "null"):
            with self.assertRaises(RpcError) as ctx:
                parse_request(non_obj)
            self.assertEqual(ctx.exception.code, PARSE_ERROR)
            self.assertIsNone(ctx.exception.rpc_id)

    def test_validate_envelope_success(self) -> None:
        valid = {"jsonrpc": "2.0", "id": "req-1", "method": "tools/call"}
        # Must not raise
        validate_envelope(valid)

    def test_validate_envelope_echoes_id_on_failure(self) -> None:
        # Bad jsonrpc version
        with self.assertRaises(RpcError) as ctx:
            validate_envelope({"jsonrpc": "1.0", "id": "my-id-123", "method": "tools/call"})
        self.assertEqual(ctx.exception.code, INVALID_REQUEST)
        self.assertEqual(ctx.exception.rpc_id, "my-id-123")

        # Missing jsonrpc
        with self.assertRaises(RpcError) as ctx:
            validate_envelope({"id": 456, "method": "tools/call"})
        self.assertEqual(ctx.exception.code, INVALID_REQUEST)
        self.assertEqual(ctx.exception.rpc_id, 456)

        # Missing method
        with self.assertRaises(RpcError) as ctx:
            validate_envelope({"jsonrpc": "2.0", "id": "id-789"})
        self.assertEqual(ctx.exception.code, INVALID_REQUEST)
        self.assertEqual(ctx.exception.rpc_id, "id-789")

        # Non-string method
        with self.assertRaises(RpcError) as ctx:
            validate_envelope({"jsonrpc": "2.0", "id": "id-1", "method": 123})
        self.assertEqual(ctx.exception.code, INVALID_REQUEST)
        self.assertEqual(ctx.exception.rpc_id, "id-1")

    def test_validate_envelope_null_id_when_id_unreadable(self) -> None:
        # Missing id key
        with self.assertRaises(RpcError) as ctx:
            validate_envelope({"jsonrpc": "2.0", "method": "tools/call"})
        self.assertEqual(ctx.exception.code, INVALID_REQUEST)
        self.assertIsNone(ctx.exception.rpc_id)

        # Non-dict raw
        with self.assertRaises(RpcError) as ctx:
            validate_envelope([1, 2, 3])
        self.assertEqual(ctx.exception.code, INVALID_REQUEST)
        self.assertIsNone(ctx.exception.rpc_id)


if __name__ == "__main__":
    unittest.main()
