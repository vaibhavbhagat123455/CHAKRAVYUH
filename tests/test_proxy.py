"""Tests for ProxyServer and end-to-end proxy processing flows."""

import unittest

from proxy.config import ProxyConfig
from proxy.models import ToolRequest
from proxy.server import ProxyServer
from tests.fakes import (
    FakeAnalyser,
    FakeApprovalService,
    FakeClock,
    FakeLog,
    SpyExecutor,
)


class TestProxyServerBasic(unittest.TestCase):
    """Test ProxyServer dependency injection and initial request logging."""

    def setUp(self) -> None:
        self.log = FakeLog()
        self.analyser = FakeAnalyser()
        self.executor = SpyExecutor()
        self.approval = FakeApprovalService()
        self.config = ProxyConfig()
        self.clock = FakeClock()
        self.server = ProxyServer(
            log=self.log,
            analyser=self.analyser,
            executor=self.executor,
            approval=self.approval,
            config=self.config,
            clock=self.clock,
        )
        self.request = ToolRequest(
            request_id="req-srv-01",
            tool="summarize_document",
            arguments={"file": "synthetic_report.pdf"},
            purpose="Summarize document",
            scenario_id="scen-srv-01",
        )

    def test_handle_tool_call_emits_request_received_first(self) -> None:
        response = self.server.handle_tool_call(self.request)
        self.assertIsNotNone(response)

        events = self.log.get_events_for_request("req-srv-01")
        self.assertEqual(len(events), 1)
        first_evt = events[0]
        self.assertEqual(first_evt["event_type"], "REQUEST_RECEIVED")
        self.assertEqual(first_evt["payload"]["request_id"], "req-srv-01")
        self.assertEqual(first_evt["payload"]["tool"], "summarize_document")
        self.assertEqual(first_evt["payload"]["arguments"], {"file": "synthetic_report.pdf"})
        self.assertEqual(first_evt["payload"]["purpose"], "Summarize document")
        self.assertEqual(first_evt["payload"]["scenario_id"], "scen-srv-01")


if __name__ == "__main__":
    unittest.main()
