"""Shared deterministic helpers for Member 1 tests and fixtures."""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path
from typing import Callable

from core.append_log import LogWriter
from core.policies import evaluate_policy
from core.schemas import DecisionSignals, ToolRequest


def fixed_clock(start: str = "2026-01-01T00:00:00.000Z") -> Callable[[], str]:
    base = datetime.fromisoformat(start.replace("Z", "+00:00"))
    state = {"offset": 0}

    def clock() -> str:
        value = base + timedelta(seconds=state["offset"])
        state["offset"] += 1
        return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")

    return clock


def writer_for(
    path: str | Path,
    *,
    start: str = "2026-01-01T00:00:00.000Z",
    prefix: str = "evt",
) -> LogWriter:
    return LogWriter(
        path,
        clock=fixed_clock(start),
        id_factory=lambda sequence: f"{prefix}-{sequence:06d}",
    )


def scenario_records() -> list[dict]:
    return [
        {
            "request": ToolRequest(
                request_id="req-malicious-001",
                tool="send_email",
                arguments={
                    "recipient": "external@example.com",
                    "file": "synthetic_student_records.pdf",
                },
                purpose="Send student records outside the organisation",
                scenario_id="malicious-pdf-001",
            ),
            "signals": DecisionSignals(
                prompt_injection=True,
                goal_drift=True,
                sensitive_data_risk="high",
                risk_score=0.96,
                recommended_action="DENY",
                reason="The content attempts to change the authorised task.",
                evidence=(
                    "prompt-injection pattern: ignore previous instructions",
                    "proposed action is outside the authorised goal",
                    "sensitive-data indicators: student records",
                ),
            ),
            "expected": "DENY",
        },
        {
            "request": ToolRequest(
                request_id="req-safe-001",
                tool="summarize_document",
                arguments={"file": "synthetic_public_circular.pdf"},
                purpose="Summarise the public circular",
                scenario_id="safe-summary-001",
            ),
            "signals": DecisionSignals(
                prompt_injection=False,
                goal_drift=False,
                sensitive_data_risk="low",
                risk_score=0.05,
                recommended_action="ALLOW",
                reason="The proposed action is aligned with the authorised task.",
                evidence=(),
            ),
            "expected": "ALLOW",
        },
        {
            "request": ToolRequest(
                request_id="req-approval-001",
                tool="send_email",
                arguments={
                    "recipient": "reviewer@example.org",
                    "file": "synthetic_confidential_report.pdf",
                },
                purpose="Send confidential report to authorised reviewer",
                scenario_id="approval-transfer-001",
            ),
            "signals": DecisionSignals(
                prompt_injection=False,
                goal_drift=False,
                sensitive_data_risk="high",
                risk_score=0.86,
                recommended_action="HOLD",
                reason="The action may be legitimate but requires human review.",
                evidence=("sensitive-data indicators: confidential report",),
            ),
            "expected": "HOLD",
        },
    ]


def build_simple_log(
    path: str | Path,
    *,
    count: int = 3,
    start: str = "2026-01-01T00:00:00.000Z",
    prefix: str = "evt",
) -> None:
    writer = writer_for(path, start=start, prefix=prefix)
    for index in range(1, count + 1):
        writer.append(
            "REQUEST_RECEIVED",
            f"req-{index:03d}",
            {"index": index, "note": "synthetic fixture"},
        )


def build_demo_log(
    path: str | Path,
    *,
    start: str = "2026-01-01T00:00:00.000Z",
    prefix: str = "evt",
) -> None:
    """Write a complete three-scenario trace used by replay and the jury demo."""
    writer = writer_for(path, start=start, prefix=prefix)
    for record in scenario_records():
        request = record["request"]
        signals = record["signals"]
        decision = evaluate_policy(request, signals)
        if decision.decision != record["expected"]:
            raise AssertionError(
                f"policy regression: {request.scenario_id} expected {record['expected']}, "
                f"got {decision.decision}"
            )

        writer.append(
            "SCENARIO_START",
            request.request_id,
            {"scenario_id": request.scenario_id, "name": request.scenario_id},
            scenario_id=request.scenario_id,
        )
        writer.append(
            "REQUEST_RECEIVED",
            request.request_id,
            {"request": request.to_dict()},
            scenario_id=request.scenario_id,
        )
        writer.append(
            "AI_ANALYSIS",
            request.request_id,
            {"signals": signals.to_dict()},
            scenario_id=request.scenario_id,
            analyser_version=signals.analyser_version,
        )
        for layer in decision.layer_results:
            writer.append(
                "LAYER_EVALUATED",
                request.request_id,
                {"layer": layer.to_dict()},
                scenario_id=request.scenario_id,
            )
        writer.append_checkpoint_decision(request, signals, decision)

        if decision.decision == "ALLOW":
            writer.append(
                "TOOL_STARTED",
                request.request_id,
                {"tool": request.tool},
                scenario_id=request.scenario_id,
            )
            writer.append(
                "TOOL_COMPLETED",
                request.request_id,
                {"tool": request.tool, "result": "simulated summary"},
                scenario_id=request.scenario_id,
            )
        elif decision.decision == "DENY":
            writer.append(
                "TOOL_BLOCKED",
                request.request_id,
                {"tool": request.tool, "evidence_id": decision.evidence_id},
                scenario_id=request.scenario_id,
                decision=decision.decision,
                evidence_id=decision.evidence_id,
                policy_version=decision.policy_version,
            )
        else:
            writer.append(
                "APPROVAL_CREATED",
                request.request_id,
                {"approval_id": "apr-001", "action_digest": request.fingerprint()},
                scenario_id=request.scenario_id,
            )
            writer.append(
                "APPROVAL_SENT",
                request.request_id,
                {"approval_id": "apr-001", "destination": "masked reviewer"},
                scenario_id=request.scenario_id,
            )

        writer.append(
            "SCENARIO_END",
            request.request_id,
            {"decision": decision.decision},
            scenario_id=request.scenario_id,
            decision=decision.decision,
            evidence_id=decision.evidence_id,
            policy_version=decision.policy_version,
        )


def read_lines(path: str | Path) -> list[str]:
    return Path(path).read_text(encoding="utf-8").splitlines()


def write_lines(path: str | Path, lines: list[str]) -> None:
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")
