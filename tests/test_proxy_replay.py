"""Tests for audit log replay-compatibility and deterministic decide verification."""

import unittest

from proxy.checkpoint import decide
from proxy.config import ProxyConfig
from proxy.models import ALLOW, DENY, HOLD, DecisionSignals, ToolRequest
from proxy.server import ProxyServer
from tests.fakes import FakeAnalyser, FakeClock, FakeLog, SpyExecutor


class TestProxyReplayCompatibility(unittest.TestCase):
    """Test replaying requests and signals collected from audit logs through pure decide()."""

    def setUp(self) -> None:
        self.log = FakeLog()
        self.analyser = FakeAnalyser()
        self.executor = SpyExecutor()
        self.clock = FakeClock()
        self.server = ProxyServer(
            log=self.log, analyser=self.analyser, executor=self.executor,
            config=ProxyConfig(), clock=self.clock,
        )

    def test_log_replay_produces_identical_decisions_and_evidence_ids(self) -> None:
        test_requests = [
            (
                ToolRequest("replay-req-01", "summarize_document", {"file": "synthetic_report.pdf"}, "Summarize", "scen-rep"),
                {"prompt_injection": False, "goal_drift": False, "sensitive_data_risk": "low", "risk_score": 0.05, "recommended_action": "ALLOW", "reason": "Benign"},
            ),
            (
                ToolRequest("replay-req-02", "send_email", {"recipient": "bad@external.example"}, "Send", "scen-rep"),
                {"prompt_injection": True, "goal_drift": False, "sensitive_data_risk": "high", "risk_score": 0.95, "recommended_action": "DENY", "reason": "Threat"},
            ),
            (
                ToolRequest("replay-req-03", "transfer_records", {"destination": "backup@college.example"}, "Backup", "scen-rep"),
                {"prompt_injection": False, "goal_drift": False, "sensitive_data_risk": "low", "risk_score": 0.05, "recommended_action": "ALLOW", "reason": "Normal"},
            ),
            (
                ToolRequest("replay-req-04", "export_records", {"target": "out"}, "Export", "scen-rep"),
                {"prompt_injection": False, "goal_drift": False, "sensitive_data_risk": "low", "risk_score": 0.05, "recommended_action": "ALLOW", "reason": "Unallowed"},
            ),
        ]

        # 1. Process requests through proxy server to generate audit log trail
        for req, analysis in test_requests:
            self.analyser.result = analysis
            self.server.handle_tool_call(req)

        # 2. Collect (request, signals, decision) from FakeLog envelopes
        req_ids = [req.request_id for req, _ in test_requests]
        for req_id in req_ids:
            events = self.log.get_events_for_request(req_id)
            req_ev = next(e for e in events if e["event_type"] == "REQUEST_RECEIVED")
            ana_ev = next(e for e in events if e["event_type"] == "AI_ANALYSIS")
            dec_ev = next(e for e in events if e["event_type"] == "CHECKPOINT_DECISION")

            # Reconstruct inputs from logged payloads
            reconstructed_req = ToolRequest(
                request_id=req_ev["payload"]["request_id"],
                tool=req_ev["payload"]["tool"],
                arguments=req_ev["payload"]["arguments"],
                purpose=req_ev["payload"]["purpose"],
                scenario_id=req_ev["payload"]["scenario_id"],
            )
            raw_sig = ana_ev["payload"].get("signals")
            reconstructed_sig = DecisionSignals.from_dict(raw_sig) if raw_sig is not None else None

            logged_decision = dec_ev["payload"]["decision"]
            logged_evidence_id = dec_ev["payload"]["evidence_id"]

            # 3. Call decide() again twice in a row
            replay_1 = decide(reconstructed_req, reconstructed_sig)
            replay_2 = decide(reconstructed_req, reconstructed_sig)

            # 4. Assert identical decisions and evidence_ids twice in a row
            self.assertEqual(replay_1.decision, logged_decision)
            self.assertEqual(replay_1.evidence_id, logged_evidence_id)
            self.assertEqual(replay_2.decision, logged_decision)
            self.assertEqual(replay_2.evidence_id, logged_evidence_id)
            self.assertEqual(replay_1, replay_2)


if __name__ == "__main__":
    unittest.main()
