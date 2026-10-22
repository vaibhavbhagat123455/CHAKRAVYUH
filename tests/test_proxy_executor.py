"""Tests for simulated tool executor, authorization tokens, tool registry, and timeouts."""

import builtins
import socket
import time
import unittest
from unittest.mock import patch

from proxy.config import ProxyConfig
from proxy.executor import (
    SimulatedExecutor,
    ToolNotFound,
    ToolTimeout,
    send_email,
    summarize_document,
    transfer_records,
)
from proxy.models import ALLOW, DENY, HOLD, Decision, ToolRequest
from proxy.pending import PendingRecord


class TestSimulatedExecutorAuth(unittest.TestCase):
    """Test authorization token enforcement and direct tool call prevention."""

    def setUp(self) -> None:
        self.executor = SimulatedExecutor()
        self.valid_allow = Decision(
            request_id="req-auth-01",
            decision=ALLOW,
            evidence_id="ev-auth-01",
            reason="Approved summary",
            policy_version="v1",
        )
        self.req = ToolRequest(
            request_id="req-auth-01",
            tool="summarize_document",
            arguments={"file": "report.pdf"},
            purpose="Testing auth",
            scenario_id="scen-01",
        )
        self.pending_rec = PendingRecord(
            request=self.req,
            action_digest="digest-123",
            evidence_id="ev-auth-01",
            signals=None,
            created_at=1000.0,
            expires_at=1100.0,
            approval_id="appr-01",
        )

    def test_direct_tool_functions_raise_permission_error(self) -> None:
        with self.assertRaises(PermissionError):
            summarize_document({"file": "notice.pdf"})
        with self.assertRaises(PermissionError):
            send_email({"recipient": "dean@example.edu"})
        with self.assertRaises(PermissionError):
            transfer_records({"destination": "archive@example.edu"})

    def test_no_token_raises_permission_error(self) -> None:
        with self.assertRaises(PermissionError) as ctx:
            self.executor.execute("summarize_document", {"file": "report.pdf"})
        self.assertIn("authorisation token", str(ctx.exception).lower())

    def test_deny_token_raises_permission_error(self) -> None:
        deny_token = Decision(
            request_id="req-auth-01",
            decision=DENY,
            evidence_id="ev-deny",
            reason="Policy violation",
            policy_version="v1",
        )
        with self.assertRaises(PermissionError):
            self.executor.execute("summarize_document", {"file": "report.pdf"}, auth_token=deny_token)

    def test_hold_token_raises_permission_error(self) -> None:
        hold_token = Decision(
            request_id="req-auth-01",
            decision=HOLD,
            evidence_id="ev-hold",
            reason="Requires approval",
            policy_version="v1",
        )
        with self.assertRaises(PermissionError):
            self.executor.execute("summarize_document", {"file": "report.pdf"}, auth_token=hold_token)

    def test_allow_token_for_different_request_id_raises_permission_error(self) -> None:
        with self.assertRaises(PermissionError):
            self.executor.execute(
                "summarize_document", {"file": "report.pdf"},
                auth_token=self.valid_allow, request_id="req-different-99"
            )

    def test_valid_allow_token_executes_successfully(self) -> None:
        res = self.executor.execute(
            "summarize_document", {"file": "report.pdf"},
            auth_token=self.valid_allow, request_id="req-auth-01"
        )
        self.assertTrue(res["simulated"])
        self.assertIn("simulated, not sent", res["message"])

    def test_released_pending_record_executes_successfully(self) -> None:
        res = self.executor.execute(
            "summarize_document", {"file": "report.pdf"},
            auth_token=self.pending_rec, request_id="req-auth-01"
        )
        self.assertTrue(res["simulated"])


class TestSimulatedExecutorIsolation(unittest.TestCase):
    """Test simulated tool execution, timeout handling, and I/O isolation."""

    def setUp(self) -> None:
        self.executor = SimulatedExecutor()
        self.token = Decision(
            request_id="req-iso-01",
            decision=ALLOW,
            evidence_id="ev-iso-01",
            reason="Allowed",
            policy_version="v1",
        )

    def test_socket_and_open_patched_to_raise(self) -> None:
        def fail_io(*args, **kwargs):
            raise RuntimeError("Unexpected real I/O call")

        with patch.object(socket, "socket", side_effect=fail_io), \
             patch.object(builtins, "open", side_effect=fail_io):
            r1 = self.executor.execute("summarize_document", {"file": "synthetic_report.pdf"}, auth_token=self.token)
            r2 = self.executor.execute("send_email", {"recipient": "user@example.edu"}, auth_token=self.token)
            r3 = self.executor.execute("transfer_records", {"destination": "backup@example.edu"}, auth_token=self.token)

            self.assertTrue(r1["simulated"])
            self.assertTrue(r2["simulated"])
            self.assertTrue(r3["simulated"])

    def test_slow_tool_times_out(self) -> None:
        def slow_tool(args):
            time.sleep(0.5)
            return {"status": "ok"}

        slow_executor = SimulatedExecutor(
            registry={"slow_tool": slow_tool},
            timeout_seconds=0.1,
        )
        with self.assertRaises(ToolTimeout) as ctx:
            slow_executor.execute("slow_tool", {}, auth_token=self.token)
        self.assertIn("timed out", str(ctx.exception))

    def test_unknown_tool_raises_tool_not_found(self) -> None:
        with self.assertRaises(ToolNotFound) as ctx:
            self.executor.execute("unknown_custom_tool", {}, auth_token=self.token)
        self.assertIn("unknown_custom_tool", str(ctx.exception))

    def test_timeout_from_proxy_config_default(self) -> None:
        cfg = ProxyConfig(tool_timeout_seconds=3.5)
        executor = SimulatedExecutor(timeout_seconds=cfg.tool_timeout_seconds)
        self.assertEqual(executor.timeout_seconds, 3.5)


if __name__ == "__main__":
    unittest.main()
