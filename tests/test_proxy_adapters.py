"""Tests for dotted-path callable loader and adapter error handling."""

import sys
import unittest

import pytest

from proxy.adapters.callables import (
    CallableAnalyser,
    CallableApproval,
    CallableLogWriter,
)
from proxy.adapters.loader import AdapterError, load_callable
from proxy.models import ApprovalResult, DecisionSignals, ToolRequest


class TestCallableLoader(unittest.TestCase):
    """Test dynamic dotted-path callable loading and error cases."""

    def test_malformed_paths_raise_adapter_error(self) -> None:
        malformed_cases = [
            "",
            "   ",
            "no_colon_path",
            ":function_only",
            "module_only:",
            "too:many:colons",
        ]
        for path in malformed_cases:
            with self.subTest(path=path):
                with self.assertRaises(AdapterError) as ctx:
                    load_callable(path)
                self.assertIn("malformed", str(ctx.exception).lower())

    def test_missing_module_raises_adapter_error(self) -> None:
        with self.assertRaises(AdapterError) as ctx:
            load_callable("nonexistent_package_123.foo:bar")
        self.assertIn("not found", str(ctx.exception).lower())
        self.assertIn("nonexistent_package_123.foo", str(ctx.exception))

    def test_missing_attribute_raises_adapter_error(self) -> None:
        with self.assertRaises(AdapterError) as ctx:
            load_callable("math:nonexistent_function_xyz")
        self.assertIn("not found in module", str(ctx.exception).lower())

    def test_non_callable_attribute_raises_adapter_error(self) -> None:
        with self.assertRaises(AdapterError) as ctx:
            load_callable("math:pi")
        self.assertIn("not callable", str(ctx.exception).lower())

    def test_valid_builtin_callable_loads(self) -> None:
        func = load_callable("math:floor")
        self.assertTrue(callable(func))
        self.assertEqual(func(3.7), 3)


class TestCallableAdapters(unittest.TestCase):
    """Test CallableLogWriter, CallableAnalyser, and CallableApproval adapters."""

    def test_callable_log_writer(self) -> None:
        recorded = []

        def my_logger(event_type: str, payload: dict) -> dict:
            env = {"logged_type": event_type, "payload": payload}
            recorded.append(env)
            return env

        adapter = CallableLogWriter(my_logger)
        res = adapter.append_event("REQUEST_RECEIVED", {"request_id": "req-1", "tool": "test"})
        self.assertEqual(len(recorded), 1)
        self.assertEqual(res["logged_type"], "REQUEST_RECEIVED")

    def test_callable_analyser_valid_m3_shape(self) -> None:
        def my_analyser(tool_call: dict, goal: str) -> dict:
            return {
                "prompt_injection": False,
                "goal_drift": False,
                "sensitive_data_risk": "low",
                "risk_score": 0.05,
                "recommended_action": "ALLOW",
                "reason": "Safe tool invocation",
            }

        adapter = CallableAnalyser(my_analyser)
        result = adapter.analyse_tool_call({"tool": "summarize_document"}, "Goal")
        self.assertIsInstance(result, dict)
        self.assertEqual(result["recommended_action"], "ALLOW")

    def test_callable_analyser_invalid_shape_raises_value_error(self) -> None:
        def bad_analyser(tool_call: dict, goal: str) -> dict:
            return {"incomplete": "dict"}

        adapter = CallableAnalyser(bad_analyser)
        with self.assertRaises(ValueError):
            adapter.analyse_tool_call({"tool": "summarize_document"}, "Goal")

    def test_callable_approval_with_dict_and_bool_responses(self) -> None:
        created = []

        def fake_create(request: ToolRequest) -> dict:
            created.append(request)
            return {"approval_id": f"appr-{request.request_id}", "status": "pending"}

        def fake_verify_dict(code: str, request: ToolRequest) -> dict:
            return {
                "approved": code == "123456",
                "approval_id": f"appr-{request.request_id}",
                "reason": "Code verified",
            }

        req = ToolRequest("req-appr-1", "transfer_records", {"destination": "backup@college.example"}, "Backup", "scen")
        adapter = CallableApproval(create_func=fake_create, verify_func=fake_verify_dict)

        # Test creation
        create_res = adapter.create_approval(req)
        self.assertEqual(create_res["approval_id"], "appr-req-appr-1")
        self.assertEqual(len(created), 1)

        # Test successful verification converted to ApprovalResult
        appr_res = adapter.verify_approval("123456", req)
        self.assertIsInstance(appr_res, ApprovalResult)
        self.assertTrue(appr_res.approved)
        self.assertEqual(appr_res.approval_id, "appr-req-appr-1")
        self.assertEqual(len(appr_res.action_digest), 64)

        # Test failed verification converted to ApprovalResult
        rej_res = adapter.verify_approval("wrong-code", req)
        self.assertIsInstance(rej_res, ApprovalResult)
        self.assertFalse(rej_res.approved)


def test_custom_module_loaded_from_tmp_path(tmp_path: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test loading a callable from a fake module written to tmp_path."""
    mod_dir = tmp_path / "fake_pkg"
    mod_dir.mkdir()
    (mod_dir / "__init__.py").write_text("", encoding="utf-8")
    (mod_dir / "worker.py").write_text("def do_work(x):\n    return x * 2\n", encoding="utf-8")

    monkeypatch.syspath_prepend(str(tmp_path))
    loaded = load_callable("fake_pkg.worker:do_work")
    assert callable(loaded)
    assert loaded(21) == 42


if __name__ == "__main__":
    unittest.main()
