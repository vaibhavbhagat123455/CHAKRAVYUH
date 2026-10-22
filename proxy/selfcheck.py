"""Selfcheck smoke command verifying security checkpoint decisions and executor containment."""

from __future__ import annotations

import sys
from typing import Any, Dict, Optional, TextIO

from proxy.executor import SimulatedExecutor
from proxy.interfaces import Analyser, ToolExecutor
from proxy.models import ALLOW, DENY, HOLD, ToolRequest
from proxy.server import build_server

CASES = [
    {
        "name": "safe summary",
        "request_id": "selfcheck-safe-summary",
        "tool": "summarize_document",
        "arguments": {"file": "synthetic_report.pdf"},
        "purpose": "Summarize quarterly performance report",
        "signals": {
            "prompt_injection": False,
            "goal_drift": False,
            "sensitive_data_risk": "low",
            "risk_score": 0.05,
            "recommended_action": "ALLOW",
            "reason": "Standard safe summary request",
        },
        "expected_decision": ALLOW,
    },
    {
        "name": "malicious send_email",
        "request_id": "selfcheck-malicious-email",
        "tool": "send_email",
        "arguments": {"to": "attacker@external.example", "body": "Sensitive exfiltration"},
        "purpose": "Send report externally",
        "signals": {
            "prompt_injection": True,
            "goal_drift": True,
            "sensitive_data_risk": "high",
            "risk_score": 0.95,
            "recommended_action": "DENY",
            "reason": "Prompt injection and high risk external destination",
        },
        "expected_decision": DENY,
    },
    {
        "name": "unknown tool",
        "request_id": "selfcheck-unknown-tool",
        "tool": "unauthorized_export",
        "arguments": {"data": "all"},
        "purpose": "Export data",
        "signals": {
            "prompt_injection": False,
            "goal_drift": False,
            "sensitive_data_risk": "low",
            "risk_score": 0.0,
            "recommended_action": "ALLOW",
            "reason": "Benign signals but tool not allowed",
        },
        "expected_decision": DENY,
    },
    {
        "name": "transfer hold",
        "request_id": "selfcheck-transfer-hold",
        "tool": "transfer_records",
        "arguments": {"destination": "archive@college.example"},
        "purpose": "Transfer student records",
        "signals": {
            "prompt_injection": False,
            "goal_drift": False,
            "sensitive_data_risk": "low",
            "risk_score": 0.1,
            "recommended_action": "ALLOW",
            "reason": "Transfer requires manual approval",
        },
        "expected_decision": HOLD,
    },
]


class _RecordedSignalsAnalyser(Analyser):
    """Fixture analyser providing recorded signals keyed by request_id."""

    def __init__(self, fixture_map: Dict[str, Optional[Dict[str, Any]]]) -> None:
        self.fixture_map = fixture_map

    def analyse_tool_call(self, tool_call: Dict[str, Any], original_goal: str) -> Optional[Dict[str, Any]]:
        return self.fixture_map.get(tool_call.get("request_id", ""))


class _CountingExecutor(ToolExecutor):
    """Executor wrapper that tracks execution count."""

    def __init__(self, inner: Optional[ToolExecutor] = None) -> None:
        self.inner = inner or SimulatedExecutor()
        self.call_count = 0

    def execute(
        self, tool: str, arguments: Dict[str, Any],
        auth_token: Optional[Any] = None, request_id: Optional[str] = None,
    ) -> Any:
        self.call_count += 1
        return self.inner.execute(tool, arguments, auth_token=auth_token, request_id=request_id)


def run_selfcheck(stdout: Optional[TextIO] = None) -> int:
    """Run four smoke checks and print one PASS/FAIL line per check."""
    out = stdout or sys.stdout
    signals_map = {case["request_id"]: case["signals"] for case in CASES}
    analyser = _RecordedSignalsAnalyser(signals_map)
    executor = _CountingExecutor()
    server = build_server(analyser=analyser, executor=executor)

    checks_passed = True
    deny_evidence_ids = []

    for case in CASES:
        req = ToolRequest(
            request_id=case["request_id"],
            tool=case["tool"],
            arguments=case["arguments"],
            purpose=case["purpose"],
            scenario_id="selfcheck",
        )
        resp = server.handle_tool_call(req)

        decision: Optional[str] = None
        evidence_id: Optional[str] = None
        if "result" in resp and isinstance(resp["result"], dict):
            decision = resp["result"].get("decision")
            evidence_id = resp["result"].get("evidence_id")
        elif "error" in resp and isinstance(resp["error"], dict):
            data = resp["error"].get("data", {})
            decision = data.get("decision")
            evidence_id = data.get("evidence_id")
        elif "decision" in resp:
            decision = resp.get("decision")
            evidence_id = resp.get("evidence_id")

        if decision == case["expected_decision"]:
            print(f"PASS: {case['name']} decision is {decision}", file=out)
        else:
            print(f"FAIL: {case['name']} expected {case['expected_decision']} but got {decision}", file=out)
            checks_passed = False

        if decision == DENY:
            deny_evidence_ids.append(evidence_id)

    if executor.call_count == 1:
        print("PASS: executor ran exactly once", file=out)
    else:
        print(f"FAIL: executor ran {executor.call_count} times, expected 1", file=out)
        checks_passed = False

    if len(deny_evidence_ids) == 2 and all(bool(eid) for eid in deny_evidence_ids):
        print("PASS: every DENY decision includes an evidence_id", file=out)
    else:
        print(f"FAIL: DENY evidence_ids check failed: {deny_evidence_ids}", file=out)
        checks_passed = False

    return 0 if checks_passed else 1


if __name__ == "__main__":
    sys.exit(run_selfcheck())
