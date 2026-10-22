"""Tests for PendingStore, PendingRecord, and HOLD creation flows."""

import unittest

from proxy.canonical import action_digest
from proxy.config import ProxyConfig
from proxy.models import ALLOW, HOLD, DecisionSignals, ToolRequest
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

        fetched = self.store.get("req-store-01")
        self.assertEqual(fetched, record)


class TestHoldCreationInServer(unittest.TestCase):
    """Test server HOLD creation and execution isolation with concurrent requests."""

    def setUp(self) -> None:
        self.log = FakeLog()
        self.analyser = FakeAnalyser(default_result={
            "prompt_injection": False,
            "goal_drift": False,
            "sensitive_data_risk": "low",
            "risk_score": 0.05,
            "recommended_action": "ALLOW",
            "reason": "Low risk analysis",
        })
        self.executor = SpyExecutor()
        self.approval = FakeApprovalService()
        self.clock = FakeClock(start_time=2000.0)
        self.config = ProxyConfig(hold_ttl_seconds=120)
        self.server = ProxyServer(
            log=self.log,
            analyser=self.analyser,
            executor=self.executor,
            approval=self.approval,
            config=self.config,
            clock=self.clock,
        )

    def test_held_transfer_records_and_independent_safe_summary_in_one_run(self) -> None:
        trans_req = ToolRequest(
            request_id="req-trans-01",
            tool="transfer_records",
            arguments={"destination": "archive@college.example"},
            purpose="Hold transfer",
            scenario_id="scen-01",
        )
        sum_req = ToolRequest(
            request_id="req-sum-02",
            tool="summarize_document",
            arguments={"file": "synthetic_report.pdf"},
            purpose="Safe summary",
            scenario_id="scen-02",
        )

        # 1. Dispatch transfer_records: must produce immediate HOLD without blocking
        resp_trans = self.server.handle_tool_call(trans_req)
        self.assertEqual(resp_trans["decision"], HOLD)
        self.assertTrue(resp_trans["evidence_id"].startswith("ev-"))
        self.assertEqual(resp_trans["approval_id"], "appr-req-trans-01")

        # Held request did not execute
        self.assertEqual(self.executor.call_count, 0)

        # Pending record is present in store
        pending_rec = self.server.pending_store.get("req-trans-01")
        self.assertIsNotNone(pending_rec)
        self.assertEqual(pending_rec.created_at, 2000.0)
        self.assertEqual(pending_rec.expires_at, 2120.0)

        # HOLD_CREATED event logged (mapped to core APPROVAL_CREATED)
        trans_events = self.log.get_events_for_request("req-trans-01")
        appr_events = [e for e in trans_events if e["event_type"] == "APPROVAL_CREATED"]
        self.assertEqual(len(appr_events), 1)
        self.assertEqual(appr_events[0]["payload"]["subtype"], "HOLD_CREATED")
        self.assertEqual(appr_events[0]["payload"]["approval_id"], "appr-req-trans-01")

        # 2. Dispatch independent summarize_document: must ALLOW and execute
        resp_sum = self.server.handle_tool_call(sum_req)
        self.assertEqual(resp_sum["result"]["decision"], ALLOW)

        # Safe one executed, held one still did not execute
        self.assertEqual(self.executor.call_count, 1)
        self.assertEqual(self.executor.calls[0]["tool"], "summarize_document")


if __name__ == "__main__":
    unittest.main()
