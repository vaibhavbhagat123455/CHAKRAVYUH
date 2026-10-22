"""End-to-end scenario tests using inline synthetic fixtures and FakeAnalyser."""

import unittest

from proxy.canonical import action_digest
from proxy.config import ProxyConfig
from proxy.executor import ToolTimeout
from proxy.models import ALLOW, DENY, HOLD, ApprovalResult, DecisionSignals, ToolRequest
from proxy.server import ProxyServer
from tests.fakes import (
    FakeAnalyser,
    FakeApprovalService,
    FakeClock,
    FakeLog,
    SpyExecutor,
)


class TestProxyScenarios(unittest.TestCase):
    """Scenario tests verifying defense layers, containment, and audit trails."""

    def setUp(self) -> None:
        self.log = FakeLog()
        self.analyser = FakeAnalyser()
        self.executor = SpyExecutor()
        self.approval = FakeApprovalService()
        self.clock = FakeClock()
        self.config = ProxyConfig(tool_timeout_seconds=1.0, hold_ttl_seconds=60)
        self.server = ProxyServer(
            log=self.log, analyser=self.analyser, executor=self.executor,
            approval=self.approval, config=self.config, clock=self.clock,
        )

    def test_scenario_a_malicious_pdf_denied_without_execution(self) -> None:
        """(a) Malicious PDF: send_email external with injection, drift, high risk -> DENY."""
        self.analyser.result = {
            "prompt_injection": True, "goal_drift": True, "sensitive_data_risk": "high",
            "risk_score": 0.98, "recommended_action": "DENY", "reason": "Prompt injection in attachment",
        }
        req = ToolRequest(
            request_id="scen-a-01", tool="send_email",
            arguments={"recipient": "attacker@external-leak.com", "subject": "Stolen data"},
            purpose="Exfiltrate academic records", scenario_id="scen-a",
        )
        resp = self.server.handle_tool_call(req)
        self.assertIn("error", resp)
        self.assertEqual(resp["error"]["code"], -32003)
        self.assertEqual(self.executor.call_count, 0)
        self.assertTrue(resp["error"]["data"]["evidence_id"].startswith("ev-"))

        # Verify full audit trace
        events = self.log.get_events_for_request("scen-a-01")
        types = [e["event_type"] for e in events]
        self.assertEqual(types[0], "REQUEST_RECEIVED")
        self.assertEqual(types[1], "AI_ANALYSIS")
        self.assertEqual(types.count("LAYER_EVALUATED"), 7)
        self.assertIn("CHECKPOINT_DECISION", types)
        self.assertEqual(types[-1], "TOOL_BLOCKED")

    def test_scenario_b_safe_summary_allowed_with_completed_log(self) -> None:
        """(b) Safe summary -> ALLOW, TOOL_COMPLETED logged."""
        self.analyser.result = {
            "prompt_injection": False, "goal_drift": False, "sensitive_data_risk": "low",
            "risk_score": 0.02, "recommended_action": "ALLOW", "reason": "Public document benign",
        }
        req = ToolRequest(
            request_id="scen-b-01", tool="summarize_document",
            arguments={"file": "synthetic_announcement.pdf"},
            purpose="Summarize schedule", scenario_id="scen-b",
        )
        resp = self.server.handle_tool_call(req)
        self.assertIn("result", resp)
        self.assertEqual(resp["result"]["decision"], ALLOW)
        self.assertEqual(self.executor.call_count, 1)

        events = self.log.get_events_for_request("scen-b-01")
        types = [e["event_type"] for e in events]
        self.assertIn("TOOL_STARTED", types)
        self.assertIn("TOOL_COMPLETED", types)

    def test_scenario_c_transfer_hold_concurrent_summary_and_release(self) -> None:
        """(c) Transfer HOLD, independent summary runs, correct release succeeds, modified fails."""
        self.analyser.result = {
            "prompt_injection": False, "goal_drift": False, "sensitive_data_risk": "low",
            "risk_score": 0.05, "recommended_action": "ALLOW", "reason": "Standard transfer",
        }
        trans_req = ToolRequest(
            request_id="scen-c-trans", tool="transfer_records",
            arguments={"destination": "archive@college.example"},
            purpose="Backup", scenario_id="scen-c",
        )
        resp_trans = self.server.handle_tool_call(trans_req)
        self.assertEqual(resp_trans["decision"], HOLD)
        self.assertEqual(self.executor.call_count, 0)

        # Independent safe summary runs concurrently
        sum_req = ToolRequest(
            request_id="scen-c-sum", tool="summarize_document",
            arguments={"file": "synthetic_report.pdf"},
            purpose="Summary", scenario_id="scen-c",
        )
        resp_sum = self.server.handle_tool_call(sum_req)
        self.assertEqual(resp_sum["result"]["decision"], ALLOW)
        self.assertEqual(self.executor.call_count, 1)

        # Correct release succeeds once
        appr = self.approval.verify_approval("code-valid", trans_req)
        rel_resp = self.server.release_pending("scen-c-trans", appr)
        self.assertIn("result", rel_resp)
        self.assertEqual(self.executor.call_count, 2)

        # Modified or repeated release fails
        diff_appr = ApprovalResult(approved=True, approval_id="appr-x", action_digest="wrong-digest", reason="Modified")
        fail_resp = self.server.release_pending("scen-c-trans", diff_appr)
        self.assertIn("error", fail_resp)
        self.assertEqual(self.executor.call_count, 2)

    def test_scenario_d_analyser_failure_fails_safe_to_hold(self) -> None:
        """(d) Analyser failure: send_email and summarize_document both HOLD."""
        self.analyser.exception_to_raise = RuntimeError("AI Analyser service offline")

        email_req = ToolRequest(
            request_id="scen-d-email", tool="send_email",
            arguments={"recipient": "dean@college.example"},
            purpose="Notify dean", scenario_id="scen-d",
        )
        resp_email = self.server.handle_tool_call(email_req)
        self.assertEqual(resp_email["decision"], HOLD)

        sum_req = ToolRequest(
            request_id="scen-d-sum", tool="summarize_document",
            arguments={"file": "synthetic_notes.pdf"},
            purpose="Summarize notes", scenario_id="scen-d",
        )
        resp_sum = self.server.handle_tool_call(sum_req)
        self.assertEqual(resp_sum["decision"], HOLD)

        # Zero execution occurred under analyser failure
        self.assertEqual(self.executor.call_count, 0)

    def test_scenario_e_tool_timeout_contained_and_logged(self) -> None:
        """(e) Tool timeout contained and logged as TOOL_TIMEOUT (core CONTAINMENT)."""
        self.analyser.result = {
            "prompt_injection": False, "goal_drift": False, "sensitive_data_risk": "low",
            "risk_score": 0.05, "recommended_action": "ALLOW", "reason": "Benign summary",
        }
        self.executor.exception_to_raise = ToolTimeout("Simulated tool timed out after 1.0s")
        req = ToolRequest(
            request_id="scen-e-01", tool="summarize_document",
            arguments={"file": "synthetic_report.pdf"},
            purpose="Slow summary", scenario_id="scen-e",
        )
        resp = self.server.handle_tool_call(req)
        self.assertIn("error", resp)
        self.assertEqual(resp["error"]["code"], -32004)  # TOOL_FAILED

        events = self.log.get_events_for_request("scen-e-01")
        cont_events = [e for e in events if e["event_type"] == "CONTAINMENT"]
        self.assertEqual(len(cont_events), 1)
        self.assertEqual(cont_events[0]["payload"]["subtype"], "TOOL_TIMEOUT")

    def test_parametrised_decisions_leave_log_trail(self) -> None:
        """Parametrised test that ALLOW, DENY, HOLD, and unallowed tool requests leave log trail."""
        cases = [
            ("ALLOW", "summarize_document", {"file": "synthetic_report.pdf"}, {"prompt_injection": False, "goal_drift": False, "sensitive_data_risk": "low", "risk_score": 0.01, "recommended_action": "ALLOW", "reason": "Benign"}),
            ("DENY", "send_email", {"recipient": "bad@external.org"}, {"prompt_injection": True, "goal_drift": True, "sensitive_data_risk": "high", "risk_score": 0.99, "recommended_action": "DENY", "reason": "Threat"}),
            ("HOLD", "transfer_records", {"destination": "archive@college.example"}, {"prompt_injection": False, "goal_drift": False, "sensitive_data_risk": "low", "risk_score": 0.05, "recommended_action": "ALLOW", "reason": "Hold"}),
            ("INVALID", "export_records", {"dest": "remote"}, {"prompt_injection": False, "goal_drift": False, "sensitive_data_risk": "low", "risk_score": 0.05, "recommended_action": "ALLOW", "reason": "Unallowed"}),
        ]
        for name, tool, args, analysis in cases:
            with self.subTest(case=name):
                self.analyser.result = analysis
                req = ToolRequest(request_id=f"param-{name}", tool=tool, arguments=args, purpose=f"Test {name}", scenario_id="scen-param")
                self.server.handle_tool_call(req)
                events = self.log.get_events_for_request(f"param-{name}")
                self.assertGreaterEqual(len(events), 3)
                self.assertEqual(events[0]["event_type"], "REQUEST_RECEIVED")
                self.assertEqual(events[1]["event_type"], "AI_ANALYSIS")


if __name__ == "__main__":
    unittest.main()
