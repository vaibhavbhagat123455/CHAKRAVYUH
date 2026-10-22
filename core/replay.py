"""Deterministic replay of recorded checkpoint decisions."""

from __future__ import annotations

import argparse
import json
from dataclasses import replace
from pathlib import Path
from typing import Mapping, Sequence

from .canonical import sha256_hex
from .contracts import DECISIONS, POLICY_VERSION, canonical_json
from .policies import evaluate_policy
from .schemas import DecisionSignals, LogEvent, ReplayDecision, ReplayResult, ToolRequest
from .verify import verify_log


def _decision_digest(decisions: Sequence[ReplayDecision]) -> str:
    material = [
        {
            "request_id": decision.request_id,
            "decision": decision.replayed,
            "evidence_id": decision.evidence_id,
            **({"final_decision": decision.final_decision} if decision.final_decision is not None else {}),
        }
        for decision in decisions
    ]
    return "sha256:" + sha256_hex(canonical_json(material))


def _load_expected(expected: str | Path | Mapping[str, str] | None) -> dict[str, str]:
    if expected is None:
        return {}
    if isinstance(expected, Mapping):
        raw = dict(expected)
    else:
        raw = json.loads(Path(expected).read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("expected decisions must be a JSON object of request_id -> decision")
    result: dict[str, str] = {}
    for request_id, decision in raw.items():
        if not isinstance(request_id, str) or not request_id.strip():
            raise ValueError("expected decisions contains an invalid request_id")
        if decision not in DECISIONS:
            raise ValueError(f"expected decision for {request_id} is invalid: {decision!r}")
        result[request_id] = decision
    return result


def _invalid_result(log_verified: bool, error: str, decisions: Sequence[ReplayDecision] = ()) -> ReplayResult:
    return ReplayResult(
        valid=False,
        log_verified=log_verified,
        policy_version=POLICY_VERSION,
        events_replayed=len(decisions),
        decision_digest=_decision_digest(decisions),
        decisions=tuple(decisions),
        mismatches=tuple(decision for decision in decisions if not decision.match),
        error=error,
    )


def replay_log(
    path: str | Path,
    *,
    verify: bool = True,
    expected: str | Path | Mapping[str, str] | None = None,
    max_errors: int = 50,
) -> ReplayResult:
    """Replay CHECKPOINT_DECISION events without calling AI, time or network."""
    log_verified = False
    if verify:
        verification = verify_log(path, max_errors=max_errors)
        if not verification.valid:
            first = verification.first_invalid
            detail = f": {first.code} at line {first.line}" if first else ""
            return _invalid_result(False, f"security log failed verification{detail}")
        log_verified = True

    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return _invalid_result(False, f"log file does not exist: {path}")
    except UnicodeDecodeError as exc:
        return _invalid_result(False, f"log is not valid UTF-8: {exc}")

    try:
        expected_decisions = _load_expected(expected)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return _invalid_result(log_verified, f"cannot load expected decisions: {exc}")
    decisions: list[ReplayDecision] = []
    versions: set[str] = set()
    approved_outcomes: dict[str, str] = {}

    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
            event = LogEvent.from_dict(raw)
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            return _invalid_result(log_verified, f"invalid log event on line {line_number}: {exc}", decisions)
        if event.event_type == "APPROVED_RELEASE":
            if event.decision in DECISIONS:
                approved_outcomes[event.request_id] = event.decision
            continue
        if event.event_type != "CHECKPOINT_DECISION":
            continue

        if event.decision is None:
            return _invalid_result(log_verified, f"CHECKPOINT_DECISION on line {line_number} has no decision", decisions)
        if not event.evidence_id:
            return _invalid_result(log_verified, f"CHECKPOINT_DECISION on line {line_number} has no evidence_id", decisions)
        request_raw = event.payload.get("request")
        signals_raw = event.payload.get("signals")
        if not isinstance(request_raw, Mapping) or not isinstance(signals_raw, Mapping):
            return _invalid_result(
                log_verified,
                f"CHECKPOINT_DECISION on line {line_number} must contain request and signals",
                decisions,
            )
        policy_version = event.policy_version or event.payload.get("policy_version")
        if not isinstance(policy_version, str) or not policy_version:
            return _invalid_result(
                log_verified,
                f"CHECKPOINT_DECISION on line {line_number} has no policy_version",
                decisions,
            )

        try:
            request = ToolRequest.from_dict(request_raw)
            signals = DecisionSignals.from_mapping(signals_raw)
            replayed = evaluate_policy(request, signals, policy_version)
        except (KeyError, TypeError, ValueError) as exc:
            return _invalid_result(log_verified, f"cannot replay line {line_number}: {exc}", decisions)

        versions.add(policy_version)
        expected_decision = expected_decisions.get(request.request_id)
        matches_record = replayed.decision == event.decision
        matches_expected = expected_decision is None or expected_decision == event.decision
        matches_evidence = replayed.evidence_id == event.evidence_id
        decision = ReplayDecision(
            request_id=request.request_id,
            recorded=event.decision,
            replayed=replayed.decision,
            match=matches_record and matches_expected and matches_evidence,
            evidence_id=replayed.evidence_id,
            evidence_id_match=matches_evidence,
            expected=expected_decision,
        )
        decisions.append(decision)

    decisions = [replace(item, final_decision=approved_outcomes.get(item.request_id)) for item in decisions]
    unexpected = sorted(set(expected_decisions) - {decision.request_id for decision in decisions})
    if unexpected:
        return _invalid_result(
            log_verified,
            f"expected decisions are missing from the log: {unexpected}",
            decisions,
        )

    mismatches = tuple(decision for decision in decisions if not decision.match)
    policy_versions = ",".join(sorted(versions)) if versions else POLICY_VERSION
    return ReplayResult(
        valid=not mismatches,
        log_verified=log_verified,
        policy_version=policy_versions,
        events_replayed=len(decisions),
        decision_digest=_decision_digest(decisions),
        decisions=tuple(decisions),
        mismatches=mismatches,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Replay recorded AI Chakravyuh checkpoint decisions")
    parser.add_argument("path", help="path to data/security_log.jsonl")
    parser.add_argument("--output", help="write the replay report to this JSON file")
    parser.add_argument("--expected", help="optional expected_decisions.json")
    parser.add_argument("--skip-verify", action="store_true", help="debug only: replay without log verification")
    parser.add_argument("--max-errors", type=int, default=50, help="verification error limit")
    args = parser.parse_args(argv)
    result = replay_log(
        args.path,
        verify=not args.skip_verify,
        expected=args.expected,
        max_errors=args.max_errors,
    )
    encoded = json.dumps(result.to_dict(), indent=2, sort_keys=True)
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(encoded + "\n", encoding="utf-8")
    print(encoded)
    return 0 if result.valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
