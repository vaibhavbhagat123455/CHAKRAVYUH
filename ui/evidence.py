"""Dashboard evidence adapter backed by the canonical Member 1 log."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.append_log import LogWriter, utc_now_iso
from core.canonical import genesis_hash
from core.contracts import POLICY_VERSION
from core.replay import replay_log
from core.verify import verify_log

GENESIS = genesis_hash()


class EvidenceLog:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.writer = LogWriter(self.path)

    def append(self, event: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(event, dict):
            raise TypeError("event must be an object")
        event_type = event.get("event_type")
        request_id = event.get("request_id") or f"dashboard-{event.get('event_id', 'event')}"
        known = {"event_id", "timestamp", "event_type", "request_id", "scenario_id", "decision", "evidence_id", "policy_version", "analyser_version", "payload"}
        payload = dict(event.get("payload", {})) if isinstance(event.get("payload"), dict) else {}
        payload.update({key: value for key, value in event.items() if key not in known})
        timestamp = event.get("timestamp")
        # ApprovalService uses an injectable epoch clock for expiry tests. The
        # canonical security log stores UTC ISO timestamps, so convert that
        # internal clock value at the adapter boundary.
        if not isinstance(timestamp, str):
            timestamp = utc_now_iso()
        result = self.writer.append(
            event_type,
            request_id,
            payload,
            scenario_id=event.get("scenario_id"),
            decision=event.get("decision"),
            evidence_id=event.get("evidence_id"),
            policy_version=event.get("policy_version") or (POLICY_VERSION if event.get("decision") else None),
            analyser_version=event.get("analyser_version"),
            event_id=event.get("event_id"),
            timestamp=timestamp,
        )
        return result.to_dict()

    def read_entries(self) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        return [json.loads(line) for line in self.path.read_text(encoding="utf-8").splitlines() if line.strip()]

    def verify(self) -> dict[str, Any]:
        result = verify_log(self.path)
        data = result.to_dict()
        first = result.first_invalid
        data["entries"] = result.entries_checked
        if first:
            data["line_number"] = first.line
            data["event_id"] = self._event_id_at(first.line)
            data["reason"] = first.message
        return data

    def replay(self) -> dict[str, Any]:
        result = replay_log(self.path, verify=True)
        data = result.to_dict()
        data["decisions"] = [
            {"request_id": item["request_id"], "decision": item["replayed"], "evidence_id": item.get("evidence_id"),
             **({"final_decision": item["final_decision"]} if item.get("final_decision") else {})}
            for item in data.get("decisions", [])
        ]
        return data

    def _event_id_at(self, line_number: int) -> str | None:
        entries = self.read_entries()
        if 0 < line_number <= len(entries):
            return entries[line_number - 1].get("event_id")
        return None
