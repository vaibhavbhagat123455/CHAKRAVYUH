"""Tests for proxy JSON-RPC 2.0 protocol layer."""

import unittest

from proxy.jsonrpc import (
    INTERNAL_ERROR, INVALID_PARAMS, INVALID_REQUEST, METHOD_NOT_FOUND,
    PARSE_ERROR, POLICY_DENIED, SUPPORTED_METHODS, TOOL_FAILED,
    RpcError, error_response, parse_request, success_response,
    validate_envelope, validate_method, validate_request, validate_tool_call_params,
)
from tests.fakes import SpyExecutor


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
        self.assertEqual(resp, {"jsonrpc": "2.0", "id": "req-1", "result": {"status": "ok"}})
        resp2 = success_response(123, [1, 2, 3])
        self.assertEqual(resp2, {"jsonrpc": "2.0", "id": 123, "result": [1, 2, 3]})

    def test_error_response_without_data(self) -> None:
        resp = error_response("req-2", METHOD_NOT_FOUND, "Method not found")
        expected = {"jsonrpc": "2.0", "id": "req-2", "error": {"code": -32601, "message": "Method not found"}}
        self.assertEqual(resp, expected)

    def test_error_response_with_data(self) -> None:
        data = {"evidence_id": "ev-123", "decision": "DENY"}
        resp = error_response("req-3", POLICY_DENIED, "Policy denied", data=data)
        expected = {
            "jsonrpc": "2.0",
            "id": "req-3",
            "error": {"code": -32003, "message": "Policy denied", "data": data},
        }
        self.assertEqual(resp, expected)

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
        validate_envelope({"jsonrpc": "2.0", "id": "req-1", "method": "tools/call"})

    def test_validate_envelope_echoes_id_on_failure(self) -> None:
        with self.assertRaises(RpcError) as ctx:
            validate_envelope({"jsonrpc": "1.0", "id": "my-id-123", "method": "tools/call"})
        self.assertEqual((ctx.exception.code, ctx.exception.rpc_id), (INVALID_REQUEST, "my-id-123"))

        with self.assertRaises(RpcError) as ctx:
            validate_envelope({"id": 456, "method": "tools/call"})
        self.assertEqual((ctx.exception.code, ctx.exception.rpc_id), (INVALID_REQUEST, 456))

        with self.assertRaises(RpcError) as ctx:
            validate_envelope({"jsonrpc": "2.0", "id": "id-789"})
        self.assertEqual((ctx.exception.code, ctx.exception.rpc_id), (INVALID_REQUEST, "id-789"))

        with self.assertRaises(RpcError) as ctx:
            validate_envelope({"jsonrpc": "2.0", "id": "id-1", "method": 123})
        self.assertEqual((ctx.exception.code, ctx.exception.rpc_id), (INVALID_REQUEST, "id-1"))

    def test_validate_envelope_null_id_when_id_unreadable(self) -> None:
        with self.assertRaises(RpcError) as ctx:
            validate_envelope({"jsonrpc": "2.0", "method": "tools/call"})
        self.assertEqual((ctx.exception.code, ctx.exception.rpc_id), (INVALID_REQUEST, None))

        with self.assertRaises(RpcError) as ctx:
            validate_envelope([1, 2, 3])
        self.assertEqual((ctx.exception.code, ctx.exception.rpc_id), (INVALID_REQUEST, None))


class TestJsonRpcMethodsAndParams(unittest.TestCase):
    """Test method restriction and tool-call params validation."""

    def setUp(self) -> None:
        self.valid_params = {
            "request_id": "req-001",
            "tool": "summarize_document",
            "arguments": {"file": "notice.pdf"},
            "purpose": "Summarize student council notice",
            "scenario_id": "safe-01",
        }

    def test_supported_methods_defined_once(self) -> None:
        self.assertEqual(SUPPORTED_METHODS, frozenset({"tools/call"}))

    def test_unknown_method_raises_method_not_found(self) -> None:
        for bad_method in ("tools/list", "call_tool", "execute", "tools/call_unknown"):
            with self.assertRaises(RpcError) as ctx:
                validate_method(bad_method, rpc_id="id-10")
            self.assertEqual((ctx.exception.code, ctx.exception.rpc_id), (METHOD_NOT_FOUND, "id-10"))
            self.assertIn(bad_method, ctx.exception.message)

    def test_valid_method_passes(self) -> None:
        validate_method("tools/call", rpc_id="id-10")

    def test_params_not_object_raises_invalid_params(self) -> None:
        for bad_params in (None, [1, 2], "arguments", 42):
            with self.assertRaises(RpcError) as ctx:
                validate_tool_call_params(bad_params, rpc_id="id-20")
            self.assertEqual((ctx.exception.code, ctx.exception.rpc_id), (INVALID_PARAMS, "id-20"))
            self.assertIn("must be an object", ctx.exception.message)

    def test_missing_param_keys_raise_invalid_params_with_field_name(self) -> None:
        for key in ("request_id", "tool", "arguments", "purpose", "scenario_id"):
            bad = dict(self.valid_params)
            del bad[key]
            with self.assertRaises(RpcError) as ctx:
                validate_tool_call_params(bad, rpc_id="id-21")
            self.assertEqual((ctx.exception.code, ctx.exception.rpc_id), (INVALID_PARAMS, "id-21"))
            self.assertIn(key, ctx.exception.message)

    def test_unknown_param_keys_raise_invalid_params(self) -> None:
        bad = dict(self.valid_params)
        bad["unexpected_key"] = "bad"
        with self.assertRaises(RpcError) as ctx:
            validate_tool_call_params(bad, rpc_id="id-22")
        self.assertEqual((ctx.exception.code, ctx.exception.rpc_id), (INVALID_PARAMS, "id-22"))
        self.assertIn("unexpected_key", ctx.exception.message)

    def test_non_object_arguments_raise_invalid_params(self) -> None:
        for bad_args in ([1, 2, 3], "string_args", None, 100):
            bad = dict(self.valid_params)
            bad["arguments"] = bad_args
            with self.assertRaises(RpcError) as ctx:
                validate_tool_call_params(bad, rpc_id="id-23")
            self.assertEqual((ctx.exception.code, ctx.exception.rpc_id), (INVALID_PARAMS, "id-23"))
            self.assertIn("arguments", ctx.exception.message)

    def test_valid_params_pass(self) -> None:
        validate_tool_call_params(self.valid_params, rpc_id="id-24")


class TestValidateRequest(unittest.TestCase):
    """Test converting validated JSON-RPC requests into ToolRequest models."""

    def setUp(self) -> None:
        self.valid_params = {
            "request_id": "req-001",
            "tool": "summarize_document",
            "arguments": {"file": "notice.pdf", "max_length": 50},
            "purpose": "Summarize student council notice",
            "scenario_id": "safe-01",
        }
        self.valid_request = {
            "jsonrpc": "2.0",
            "id": "rpc-42",
            "method": "tools/call",
            "params": self.valid_params,
        }

    def test_roundtrip_loses_no_field(self) -> None:
        rpc_id, req = validate_request(self.valid_request)
        self.assertEqual(rpc_id, "rpc-42")
        self.assertEqual(req.to_dict(), self.valid_params)
        self.assertEqual(req.request_id, "req-001")
        self.assertEqual(req.tool, "summarize_document")
        self.assertEqual(req.arguments, {"file": "notice.pdf", "max_length": 50})
        self.assertEqual(req.purpose, "Summarize student council notice")
        self.assertEqual(req.scenario_id, "safe-01")

    def test_value_error_from_model_becomes_invalid_params(self) -> None:
        bad_req = {
            "jsonrpc": "2.0",
            "id": "rpc-99",
            "method": "tools/call",
            "params": {**self.valid_params, "purpose": "   "},
        }
        with self.assertRaises(RpcError) as ctx:
            validate_request(bad_req)
        self.assertEqual(ctx.exception.code, INVALID_PARAMS)
        self.assertEqual(ctx.exception.rpc_id, "rpc-99")
        self.assertIn("purpose", ctx.exception.message)

    def test_invalid_input_never_reaches_spy_executor(self) -> None:
        spy = SpyExecutor()

        def execute_after_validate(raw_payload):
            _, req = validate_request(raw_payload)
            return spy.execute(req.tool, req.arguments)

        bad_inputs = [
            {"jsonrpc": "2.0", "method": "tools/call", "params": self.valid_params},
            {"jsonrpc": "2.0", "id": 1, "method": "tools/unknown", "params": self.valid_params},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/call"},
            {"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"tool": "x"}},
            {"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {**self.valid_params, "tool": ""}},
        ]
        for bad in bad_inputs:
            with self.assertRaises(RpcError):
                execute_after_validate(bad)
        self.assertEqual(spy.call_count, 0)


if __name__ == "__main__":
    unittest.main()
