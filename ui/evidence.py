"""Append-only dashboard evidence log with verifiable hash chaining and replay."""

from __future__ import annotations

import hashlib
import json
import threading
from pathlib import Path
from typing import Any

from core.contracts import canonical_json

GENESIS = "0" * 64


def _canonical(value: Any) -> str:
    json.dumps(value, allow_nan=False)
    return canonical_json(value)


class EvidenceLog:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.RLock()

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            prior = self.read_entries()
            previous_hash = prior[-1]["current_hash"] if prior else GENESIS
            record = {"sequence": len(prior) + 1, **event, "previous_hash": previous_hash}
            record["current_hash"] = hashlib.sha256(_canonical(record).encode()).hexdigest()
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("ab") as stream:
                stream.write((_canonical(record) + "\n").encode())
            return record

    def read_entries(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        entries = []
        with self.path.open("r", encoding="utf-8") as stream:
            for line in stream:
                entries.append(json.loads(line))
        return entries

    def verify(self) -> dict[str, Any]:
        previous_hash = GENESIS
        try:
            with self.path.open("r", encoding="utf-8") as stream:
                for line_number, line in enumerate(stream, 1):
                    entry = json.loads(line)
                    expected_sequence = line_number
                    stored_hash = entry.get("current_hash")
                    body = {key: value for key, value in entry.items() if key != "current_hash"}
                    expected_hash = hashlib.sha256(_canonical(body).encode()).hexdigest()
                    if entry.get("sequence") != expected_sequence or entry.get("previous_hash") != previous_hash or stored_hash != expected_hash:
                        return {"valid": False, "line_number": line_number, "sequence": entry.get("sequence"),
                                "event_id": entry.get("event_id"), "reason": "sequence, previous hash, or entry hash mismatch"}
                    previous_hash = stored_hash
        except FileNotFoundError:
            return {"valid": True, "entries": 0, "head_hash": GENESIS}
        except (json.JSONDecodeError, KeyError, TypeError, ValueError):
            return {"valid": False, "line_number": 1, "reason": "invalid JSONL or malformed event"}
        return {"valid": True, "entries": line_number if 'line_number' in locals() else 0, "head_hash": previous_hash}

    def replay(self) -> dict[str, Any]:
        entries = self.read_entries()
        decisions = [{"request_id": e.get("request_id"), "decision": e.get("decision"),
                      "evidence_id": e.get("evidence_id")} for e in entries
                     if e.get("event_type") in {"SCENARIO_DECISION", "APPROVED_RELEASE"}]
        digest = hashlib.sha256(_canonical(decisions).encode()).hexdigest()
        return {"decisions": decisions, "decision_digest": digest}
