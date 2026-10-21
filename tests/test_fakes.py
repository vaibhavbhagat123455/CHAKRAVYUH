"""Unit tests verifying behavior of test doubles in tests/fakes.py."""

import unittest

from proxy.models import ApprovalResult, ToolRequest
from tests.fakes import (
    FakeAnalyser,
    FakeApprovalService,
    FakeClock,
    FakeLog,
    SpyExecutor,
)


class TestFakes(unittest.TestCase):
    """Test fake implementations."""

    def test_fake_log(self) -> None:
        log = FakeLog()
        env = log.append_event("REQUEST_RECEIVED", {"request_id": "req-1", "data": 123})
        self.assertEqual(env["sequence"], 1)
        self.assertEqual(env["event_id"], "evt-001")
        self.assertEqual(env["event_type"], "REQUEST_RECEIVED")
        self.assertEqual(env["request_id"], "req-1")
        self.assertEqual(len(log.events), 1)

        # Missing request_id raises ValueError
        with self.assertRaises(ValueError):
            log.append_event("REQUEST_RECEIVED", {"missing_req_id": True})

        # Unknown core event type raises ValueError
        with self.assertRaises(ValueError):
            log.append_event("INVALID_CORE_TYPE", {"request_id": "req-1"})

    def test_fake_analyser(self) -> None:
        analyser = FakeAnalyser(default_result={"risk_score": 0.5})
        res = analyser.analyse_tool_call({"tool": "summarize"}, "goal")
        self.assertEqual(res["risk_score"], 0.5)
        self.assertEqual(len(analyser.calls), 1)

        # Can raise configured exception
        failing_analyser = FakeAnalyser(exception_to_raise=RuntimeError("AI timeout"))
        with self.assertRaises(RuntimeError):
            failing_analyser.analyse_tool_call({}, "")

    def test_spy_executor(self) -> None:
        executor = SpyExecutor(default_result={"output": "done"})
        self.assertEqual(executor.call_count, 0)
        res = executor.execute("summarize_document", {"doc": "file.pdf"})
        self.assertEqual(res, {"output": "done"})
        self.assertEqual(executor.call_count, 1)
        self.assertEqual(executor.calls[0]["tool"], "summarize_document")
        self.assertEqual(executor.calls[0]["arguments"], {"doc": "file.pdf"})

    def test_fake_approval_service(self) -> None:
        service = FakeApprovalService(auto_approve=True)
        req = ToolRequest(
            request_id="req-appr-1",
            tool="send_email",
            arguments={"to": "dean@example.edu"},
            purpose="Send notice",
            scenario_id="sc-01",
        )
        created = service.create_approval(req)
        self.assertEqual(created["request_id"], "req-appr-1")
        self.assertTrue(len(created["action_digest"]) > 0)

        result = service.verify_approval("123456", req)
        self.assertTrue(result.approved)
        self.assertEqual(len(service.verified), 1)

    def test_fake_clock(self) -> None:
        clock = FakeClock(start_time=50.0)
        self.assertEqual(clock.now(), 50.0)
        clock.advance(10.5)
        self.assertEqual(clock.now(), 60.5)
        clock.set_time(100.0)
        self.assertEqual(clock.now(), 100.0)


if __name__ == "__main__":
    unittest.main()
