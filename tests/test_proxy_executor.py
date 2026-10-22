"""Tests for simulated tool executor, tool registry, and timeouts."""

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


class TestSimulatedExecutor(unittest.TestCase):
    """Test simulated tool execution, timeout handling, and I/O isolation."""

    def setUp(self) -> None:
        self.executor = SimulatedExecutor()

    def test_each_simulated_tool_result_marked(self) -> None:
        res_sum = summarize_document({"file": "notice.pdf"})
        self.assertTrue(res_sum["simulated"])
        self.assertIn("simulated, not sent", res_sum["message"])

        res_email = send_email({"recipient": "dean@example.edu", "body": "Hello"})
        self.assertTrue(res_email["simulated"])
        self.assertIn("simulated, not sent", res_email["message"])
        self.assertEqual(res_email["recipient"], "dean@example.edu")

        res_trans = transfer_records({"destination": "archive@example.edu"})
        self.assertTrue(res_trans["simulated"])
        self.assertIn("simulated, not sent", res_trans["message"])
        self.assertEqual(res_trans["destination"], "archive@example.edu")

    def test_socket_and_open_patched_to_raise(self) -> None:
        def fail_io(*args, **kwargs):
            raise RuntimeError("Unexpected real I/O call")

        with patch.object(socket, "socket", side_effect=fail_io), \
             patch.object(builtins, "open", side_effect=fail_io):
            r1 = self.executor.execute("summarize_document", {"file": "synthetic_report.pdf"})
            r2 = self.executor.execute("send_email", {"recipient": "user@example.edu"})
            r3 = self.executor.execute("transfer_records", {"destination": "backup@example.edu"})

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
            slow_executor.execute("slow_tool", {})
        self.assertIn("timed out", str(ctx.exception))

    def test_unknown_tool_raises_tool_not_found(self) -> None:
        with self.assertRaises(ToolNotFound) as ctx:
            self.executor.execute("unknown_custom_tool", {})
        self.assertIn("unknown_custom_tool", str(ctx.exception))

    def test_timeout_from_proxy_config_default(self) -> None:
        cfg = ProxyConfig(tool_timeout_seconds=3.5)
        executor = SimulatedExecutor(timeout_seconds=cfg.tool_timeout_seconds)
        self.assertEqual(executor.timeout_seconds, 3.5)


if __name__ == "__main__":
    unittest.main()
