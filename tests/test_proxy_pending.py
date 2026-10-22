"""Tests for PendingStore, PendingRecord, HOLD creation, and expiry handling."""

import unittest

from proxy.canonical import action_digest
from proxy.config import ProxyConfig
from proxy.models import ALLOW, HOLD, ApprovalResult, DecisionSignals, ToolRequest
from proxy.pending import PendingRecord, PendingStore
from proxy.server import ProxyServer
from tests.fakes import (
    FakeAnalyser,
    FakeApprovalService,
    FakeClock,
    FakeLog,
    SpyExecutor,
)


class TestPendingStoreBasic(unittest.TestCase):
    """Test PendingRecord structure and PendingStore operations."""

    def setUp(self) -> None:
        self.clock = FakeClock(start_time=1000.0)
        self.config = ProxyConfig(hold_ttl_seconds=90)
        self.store = PendingStore(clock=self.clock, hold_ttl_seconds=self.config.hold_ttl_seconds)
        self.request = ToolRequest(
            request_id="req-store-01",
            tool="transfer_records",
            arguments={"destination": "backup@college.example"},
            purpose="Transfer backup",
            scenario_id="scen-store-01",
        )

    def test_add_and_retrieve_record(self) -> None:
        expected_digest = action_digest(self.request.tool, self.request.arguments)
        record = self.store.add(
            request=self.request,
            evidence_id="ev-1234567890ab",
            signals=None,
            approval_id="appr-req-store-01",
        )
        self.assertIsInstance(record, PendingRecord)
        self.assertEqual(record.created_at, 1000.0)
        self.assertEqual(record.expires_at, 1090.0)
        self.assertEqual(record.action_digest, expected_digest)
        self.assertEqual(record.approval_id, "appr-req-store-01")
        self.assertEqual(self.store.get("req-store-01"), record)

    def test_store_expiry_methods(self) -> None:
        self.store.add(self.request, "ev-1", None, "appr-1")
        self.clock.advance(100.0)
        expired = self.store.expire_due()
        self.assertEqual(len(expired), 1)
        self.assertEqual(expired[0].request.request_id, "req-store-01")
        self.assertIsNone(self.store.get("req-store-01"))


class TestHoldCreationInServer(unittest.TestCase):
    """Test server HOLD creation and execution isolation with concurrent requests."""

    def setUp(self) -> None:
        self.log = FakeLog()
        self.analyser = FakeAnalyser(default_result={
            "prompt_injection": False, "goal_drift": False,
            "sensitive_data_risk": "low", "risk_score": 0.05,
            "recommended_action": "ALLOW", "reason": "Low risk analysis",
        })
        self.executor = SpyExecutor()
        self.approval = FakeApprovalService()
        self.clock = FakeClock(start_time=2000.0)
        self.server = ProxyServer(
            log=self.log, analyser=self.analyser, executor=self.executor,
            approval=self.approval, config=ProxyConfig(hold_ttl_seconds=120), clock=self.clock,
        )

    def test_held_transfer_records_and_independent_safe_summary_in_one_run(self) -> None:
        trans_req = ToolRequest(
            request_id="req-trans-01", tool="transfer_records",
            arguments={"destination": "archive@college.example"},
            purpose="Hold transfer", scenario_id="scen-01",
        )
        sum_req = ToolRequest(
            request_id="req-sum-02", tool="summarize_document",
            arguments={"file": "synthetic_report.pdf"},
            purpose="Safe summary", scenario_id="scen-02",
        )

        resp_trans = self.server.handle_tool_call(trans_req)
        self.assertEqual(resp_trans["decision"], HOLD)
        self.assertTrue(resp_trans["evidence_id"].startswith("ev-"))
        self.assertEqual(resp_trans["approval_id"], "appr-req-trans-01")
        self.assertEqual(self.executor.call_count, 0)

        pending_rec = self.server.pending_store.get("req-trans-01")
        self.assertIsNotNone(pending_rec)
        self.assertEqual(pending_rec.created_at, 2000.0)
        self.assertEqual(pending_rec.expires_at, 2120.0)

        trans_events = self.log.get_events_for_request("req-trans-01")
        appr_events = [e for e in trans_events if e["event_type"] == "APPROVAL_CREATED"]
        self.assertEqual(len(appr_events), 1)
        self.assertEqual(appr_events[0]["payload"]["subtype"], "HOLD_CREATED")
        self.assertEqual(appr_events[0]["payload"]["approval_id"], "appr-req-trans-01")

        resp_sum = self.server.handle_tool_call(sum_req)
        self.assertEqual(resp_sum["result"]["decision"], ALLOW)
        self.assertEqual(self.executor.call_count, 1)
        self.assertEqual(self.executor.calls[0]["tool"], "summarize_document")


class TestReleasePendingInServer(unittest.TestCase):
    """Test ProxyServer.release_pending digest verification and lifecycle."""

    def setUp(self) -> None:
        self.log = FakeLog()
        self.analyser = FakeAnalyser(default_result={
            "prompt_injection": False, "goal_drift": False,
            "sensitive_data_risk": "low", "risk_score": 0.05,
            "recommended_action": "ALLOW", "reason": "Safe analysis",
        })
        self.executor = SpyExecutor()
        self.approval = FakeApprovalService()
        self.clock = FakeClock(start_time=3000.0)
        self.server = ProxyServer(
            log=self.log, analyser=self.analyser, executor=self.executor,
            approval=self.approval, config=ProxyConfig(hold_ttl_seconds=100), clock=self.clock,
        )
        self.request = ToolRequest(
            request_id="req-rel-01", tool="transfer_records",
            arguments={"destination": "archive@college.example"},
            purpose="Transfer records", scenario_id="scen-rel-01",
        )
        self.server.handle_tool_call(self.request)

    def test_successful_release_and_execution(self) -> None:
        appr_result = self.approval.verify_approval("code123", self.request)
        resp = self.server.release_pending("req-rel-01", appr_result)
        self.assertIn("result", resp)
        self.assertEqual(self.executor.call_count, 1)
        self.assertIsNone(self.server.pending_store.get("req-rel-01"))

        events = self.log.get_events_for_request("req-rel-01")
        rel_events = [e for e in events if e.get("payload", {}).get("subtype") == "HOLD_RELEASED"]
        self.assertEqual(len(rel_events), 1)
        self.assertEqual(rel_events[0]["event_type"], "APPROVAL_ATTEMPT")
        self.assertEqual(rel_events[0]["payload"]["outcome"], "released")

    def test_approval_for_send_email_cannot_release_transfer_records(self) -> None:
        email_digest = action_digest("send_email", {"to": "alice@college.example", "body": "hi"})
        mismatched_appr = ApprovalResult(
            approved=True, approval_id="appr-req-rel-01",
            action_digest=email_digest, reason="Wrong tool approved",
        )
        resp = self.server.release_pending("req-rel-01", mismatched_appr)
        self.assertIn("error", resp)
        self.assertEqual(self.executor.call_count, 0)
        self.assertIsNone(self.server.pending_store.get("req-rel-01"))

        events = self.log.get_events_for_request("req-rel-01")
        denied_events = [e for e in events if e.get("payload", {}).get("subtype") == "HOLD_DENIED"]
        self.assertEqual(len(denied_events), 1)
        self.assertEqual(denied_events[0]["payload"]["outcome"], "denied")

    def test_double_release_fails(self) -> None:
        appr_result = self.approval.verify_approval("code123", self.request)
        first_resp = self.server.release_pending("req-rel-01", appr_result)
        self.assertIn("result", first_resp)
        self.assertEqual(self.executor.call_count, 1)

        second_resp = self.server.release_pending("req-rel-01", appr_result)
        self.assertIn("error", second_resp)
        self.assertEqual(self.executor.call_count, 1)

        events = self.log.get_events_for_request("req-rel-01")
        denied_events = [e for e in events if e.get("payload", {}).get("subtype") == "HOLD_DENIED"]
        self.assertEqual(len(denied_events), 1)

    def test_expired_release_emits_hold_expired(self) -> None:
        self.clock.advance(150.0)  # expires at 3100.0, now 3150.0
        appr_result = self.approval.verify_approval("code123", self.request)
        resp = self.server.release_pending("req-rel-01", appr_result)
        self.assertIn("error", resp)
        self.assertEqual(self.executor.call_count, 0)
        self.assertIsNone(self.server.pending_store.get("req-rel-01"))

        events = self.log.get_events_for_request("req-rel-01")
        exp_events = [e for e in events if e.get("payload", {}).get("subtype") == "HOLD_EXPIRED"]
        self.assertEqual(len(exp_events), 1)
        self.assertEqual(exp_events[0]["payload"]["outcome"], "expired")


class TestExpiryHandlingInServer(unittest.TestCase):
    """Test expiry handling using FakeClock."""

    def setUp(self) -> None:
        self.log = FakeLog()
        self.analyser = FakeAnalyser(default_result={
            "prompt_injection": False, "goal_drift": False,
            "sensitive_data_risk": "low", "risk_score": 0.05,
            "recommended_action": "ALLOW", "reason": "Safe",
        })
        self.clock = FakeClock(start_time=1000.0)
        self.server = ProxyServer(
            log=self.log, analyser=self.analyser, executor=SpyExecutor(),
            approval=FakeApprovalService(), config=ProxyConfig(hold_ttl_seconds=60),
            clock=self.clock,
        )

    def test_expire_pending_removes_and_emits(self) -> None:
        req = ToolRequest("req-exp-1", "transfer_records", {"destination": "a@b.com"}, "test", "scen")
        self.server.handle_tool_call(req)
        self.assertIsNotNone(self.server.pending_store.get("req-exp-1"))

        rec = self.server.expire_pending("req-exp-1")
        self.assertIsNotNone(rec)
        self.assertIsNone(self.server.pending_store.get("req-exp-1"))
        events = self.log.get_events_for_request("req-exp-1")
        exp_ev = [e for e in events if e.get("payload", {}).get("subtype") == "HOLD_EXPIRED"]
        self.assertEqual(len(exp_ev), 1)
        self.assertEqual(exp_ev[0]["payload"]["outcome"], "expired")
        self.assertIsNone(self.server.expire_pending("req-exp-1"))

    def test_expire_due_removes_only_overdue_records(self) -> None:
        req1 = ToolRequest("req-due-1", "transfer_records", {"destination": "a@b.com"}, "t1", "scen")
        self.server.handle_tool_call(req1)

        self.clock.advance(30.0)  # t = 1030
        req2 = ToolRequest("req-due-2", "transfer_records", {"destination": "c@d.com"}, "t2", "scen")
        self.server.handle_tool_call(req2)  # expires at 1090

        self.clock.advance(35.0)  # t = 1065 (req1 expired at 1060, req2 expires at 1090)
        expired = self.server.expire_due()
        self.assertEqual([r.request.request_id for r in expired], ["req-due-1"])
        self.assertIsNone(self.server.pending_store.get("req-due-1"))
        self.assertIsNotNone(self.server.pending_store.get("req-due-2"))

        self.clock.advance(30.0)  # t = 1095 (req2 now expired)
        expired2 = self.server.expire_due()
        self.assertEqual([r.request.request_id for r in expired2], ["req-due-2"])
        self.assertIsNone(self.server.pending_store.get("req-due-2"))


if __name__ == "__main__":
    unittest.main()
