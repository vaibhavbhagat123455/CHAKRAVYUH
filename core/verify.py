"""Tamper-evident verification for the append-only security log."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from .canonical import GENESIS, compute_entry_hash, genesis_hash
from .schemas import LogEvent, VerificationError, VerificationResult

_ALLOWED_FIELDS = {
    "sequence",
    "event_id",
    "timestamp",
    "event_type",
    "request_id",
    "payload",
    "previous_hash",
    "entry_hash",
    "scenario_id",
    "decision",
    "evidence_id",
    "policy_version",
    "analyser_version",
}
_REQUIRED_FIELDS = {
    "sequence",
    "event_id",
    "timestamp",
    "event_type",
    "request_id",
    "payload",
    "previous_hash",
    "entry_hash",
}


def verify_log(path: str | Path, *, max_errors: int = 50) -> VerificationResult:
    path = Path(path)
    if not path.exists():
        return VerificationResult(
            valid=False,
            log_path=str(path),
            entries_checked=0,
            genesis=GENESIS,
            errors=(VerificationError(0, "FILE_NOT_FOUND", f"log file does not exist: {path}"),),
        )

    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        return VerificationResult(
            valid=False,
            log_path=str(path),
            entries_checked=0,
            genesis=GENESIS,
            errors=(VerificationError(0, "INVALID_ENCODING", f"log is not valid UTF-8: {exc}"),),
        )

    if not text.strip():
        return VerificationResult(valid=True, log_path=str(path), entries_checked=0, genesis=GENESIS)

    errors: list[VerificationError] = []
    if not text.endswith("\n"):
        errors.append(
            VerificationError(
                text.count("\n") + 1,
                "MISSING_FINAL_NEWLINE",
                "every log event must end with a newline",
            )
        )

    expected_sequence = 1
    expected_previous_hash = genesis_hash()
    seen_event_ids: set[str] = set()
    entries_checked = 0

    for line_number, line in enumerate(text.splitlines(), start=1):
        if len(errors) >= max_errors:
            break
        if not line.strip():
            errors.append(VerificationError(line_number, "BLANK_LINE", "log contains a blank line"))
            expected_sequence += 1
            continue

        try:
            raw = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append(
                VerificationError(
                    line_number,
                    "INVALID_JSON",
                    f"line is not valid JSON: {exc.msg}",
                )
            )
            expected_sequence += 1
            continue

        if not isinstance(raw, dict):
            errors.append(
                VerificationError(line_number, "INVALID_EVENT", "log event must be a JSON object")
            )
            expected_sequence += 1
            continue

        sequence = raw.get("sequence")
        event_id = raw.get("event_id") if isinstance(raw.get("event_id"), str) else None
        entries_checked += 1

        missing = sorted(_REQUIRED_FIELDS - raw.keys())
        if missing:
            errors.append(
                VerificationError(
                    line_number,
                    "MISSING_FIELD",
                    f"log event is missing required fields: {missing}",
                    sequence=sequence if isinstance(sequence, int) else None,
                    event_id=event_id,
                )
            )
            continue

        unknown = sorted(raw.keys() - _ALLOWED_FIELDS)
        if unknown:
            errors.append(
                VerificationError(
                    line_number,
                    "UNKNOWN_FIELD",
                    f"log event has unknown fields: {unknown}",
                    sequence=sequence if isinstance(sequence, int) else None,
                    event_id=event_id,
                )
            )

        try:
            event = LogEvent.from_dict(raw)
        except (KeyError, TypeError, ValueError) as exc:
            errors.append(
                VerificationError(
                    line_number,
                    "INVALID_EVENT",
                    f"log event violates the contract: {exc}",
                    sequence=sequence if isinstance(sequence, int) else None,
                    event_id=event_id,
                )
            )
            if isinstance(sequence, int) and sequence >= 1:
                expected_sequence = sequence + 1
            continue

        if event.sequence != expected_sequence:
            errors.append(
                VerificationError(
                    line_number,
                    "SEQUENCE_MISMATCH",
                    "sequence is not the next expected value",
                    sequence=event.sequence,
                    event_id=event.event_id,
                    expected=expected_sequence,
                    actual=event.sequence,
                )
            )
            expected_sequence = event.sequence + 1
        else:
            expected_sequence += 1

        if event.event_id in seen_event_ids:
            errors.append(
                VerificationError(
                    line_number,
                    "DUPLICATE_EVENT_ID",
                    "event_id appears more than once",
                    sequence=event.sequence,
                    event_id=event.event_id,
                )
            )
        seen_event_ids.add(event.event_id)

        if event.event_type == "CHECKPOINT_DECISION":
            missing_checkpoint = [
                field_name
                for field_name in ("decision", "evidence_id", "policy_version")
                if getattr(event, field_name) is None
            ]
            for field_name in ("request", "signals"):
                if not isinstance(event.payload.get(field_name), dict):
                    missing_checkpoint.append(f"payload.{field_name}")
            if missing_checkpoint:
                errors.append(
                    VerificationError(
                        line_number,
                        "CHECKPOINT_CONTRACT",
                        f"CHECKPOINT_DECISION is missing replay fields: {missing_checkpoint}",
                        sequence=event.sequence,
                        event_id=event.event_id,
                    )
                )

        if event.previous_hash != expected_previous_hash:
            errors.append(
                VerificationError(
                    line_number,
                    "PREVIOUS_HASH_MISMATCH",
                    "previous_hash does not point at the prior computed entry_hash",
                    sequence=event.sequence,
                    event_id=event.event_id,
                    expected=expected_previous_hash,
                    actual=event.previous_hash,
                )
            )

        raw_without_hash = {key: value for key, value in raw.items() if key != "entry_hash"}
        recomputed = compute_entry_hash(event.previous_hash, raw_without_hash)
        if event.entry_hash != recomputed:
            errors.append(
                VerificationError(
                    line_number,
                    "ENTRY_HASH_MISMATCH",
                    "entry_hash does not match the canonical event",
                    sequence=event.sequence,
                    event_id=event.event_id,
                    expected=recomputed,
                    actual=event.entry_hash,
                )
            )
        expected_previous_hash = recomputed

    return VerificationResult(
        valid=not errors,
        log_path=str(path),
        entries_checked=entries_checked,
        genesis=GENESIS,
        errors=tuple(errors),
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify an AI Chakravyuh security log")
    parser.add_argument("path", help="path to data/security_log.jsonl")
    parser.add_argument("--max-errors", type=int, default=50, help="stop after this many errors")
    args = parser.parse_args(argv)
    result = verify_log(args.path, max_errors=args.max_errors)
    print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    return 0 if result.valid else 1


if __name__ == "__main__":
    raise SystemExit(main())
