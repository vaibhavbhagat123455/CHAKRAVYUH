"""Tests for proxy typing protocols."""

import unittest
from typing import Any, Dict

from proxy.interfaces import (
    Analyser,
    ApprovalService,
    Clock,
    LogWriter,
    ToolExecutor,
)
from proxy.models import ApprovalResult, ToolRequest


class DummyLogWriter:
    def append_event(self, event_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        return {}


class DummyAnalyser:
    def analyse_tool_call(self, tool_call: Dict[str, Any], original_goal: str) -> Dict[str, Any]:
        return {}


class DummyApprovalService:
    def create_approval(self, request: ToolRequest) -> Dict[str, Any]:
        return {}

    def verify_approval(self, code: str, request: ToolRequest) -> ApprovalResult:
        return ApprovalResult(approved=True, approval_id="appr-1", action_digest="dig", reason="ok")


class DummyToolExecutor:
    def execute(self, tool: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        return {}


class DummyClock:
    def now(self) -> float:
        return 100.0


class TestProxyInterfaces(unittest.TestCase):
    """Verify runtime checkability of proxy protocols."""

    def test_protocols_runtime_checkable(self) -> None:
        self.assertIsInstance(DummyLogWriter(), LogWriter)
        self.assertIsInstance(DummyAnalyser(), Analyser)
        self.assertIsInstance(DummyApprovalService(), ApprovalService)
        self.assertIsInstance(DummyToolExecutor(), ToolExecutor)
        self.assertIsInstance(DummyClock(), Clock)

        # Incomplete class does not implement protocol
        class Incomplete:
            pass

        self.assertNotIsInstance(Incomplete(), LogWriter)
        self.assertNotIsInstance(Incomplete(), ToolExecutor)


if __name__ == "__main__":
    unittest.main()
