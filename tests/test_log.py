import json
import tempfile
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from core.append_log import LogCorruptionError, LogWriter, REDACTED, read_last_event
from core.canonical import GENESIS, compute_entry_hash, genesis_hash
from core.contracts import canonical_json
from core.policies import evaluate_policy
from core.verify import verify_log
from tests.log_helpers import (
    build_simple_log,
    read_lines,
    scenario_records,
    write_lines,
    writer_for,
)

ROOT = Path(__file__).parents[1]


class LogTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.path = Path(self.tempdir.name) / "security_log.jsonl"

    def test_genesis_hash_is_documented_value(self):
        self.assertEqual(GENESIS, "GENESIS_AI_CHAKRAVYUH_V1")
        self.assertEqual(
            genesis_hash(),
            "cf2aae822d95ee24ec263240279a1d80b7f7e0075e9473cb3b17b1b663f1b99e",
        )

    def test_append_to_empty_log_uses_genesis(self):
        event = writer_for(self.path).append("REQUEST_RECEIVED", "req-001", {"index": 1})
        self.assertEqual(event.sequence, 1)
        self.assertEqual(event.previous_hash, genesis_hash())
        self.assertEqual(
            event.entry_hash,
            compute_entry_hash(event.previous_hash, event.canonical_dict()),
        )
        self.assertEqual(read_lines(self.path), [event.to_json_line().rstrip("\n")])

    def test_second_append_links_previous_hash(self):
        writer = writer_for(self.path)
        first = writer.append("REQUEST_RECEIVED", "req-001", {"index": 1})
        second = writer.append("REQUEST_RECEIVED", "req-002", {"index": 2})
        self.assertEqual(second.sequence, 2)
        self.assertEqual(second.previous_hash, first.entry_hash)
        self.assertEqual(len(read_lines(self.path)), 2)

    def test_append_returns_complete_event_and_writes_newline(self):
        event = writer_for(self.path).append("REQUEST_RECEIVED", "req-001", {"index": 1})
        self.assertTrue(event.event_id)
        self.assertTrue(event.timestamp.endswith("Z"))
        self.assertTrue(self.path.read_text(encoding="utf-8").endswith("\n"))
        self.assertEqual(read_last_event(self.path), event)

    def test_append_escapes_newlines_in_payload(self):
        writer_for(self.path).append(
            "REQUEST_RECEIVED",
            "req-001",
            {"note": "line one\nline two"},
        )
        lines = read_lines(self.path)
        self.assertEqual(len(lines), 1)
        self.assertEqual(json.loads(lines[0])["payload"]["note"], "line one\nline two")

    def test_append_rejects_non_json_payload(self):
        with self.assertRaises(ValueError):
            writer_for(self.path).append("REQUEST_RECEIVED", "req-001", {"bad": {1, 2}})

    def test_append_redacts_secret_fields(self):
        writer_for(self.path).append(
            "APPROVAL_CREATED",
            "req-001",
            {
                "approval_code": "123456",
                "approvalCode": "654321",
                "apiKey": "sk-synthetic",
                "nested": {"password": "hunter2", "safe": "visible"},
            },
        )
        text = self.path.read_text(encoding="utf-8")
        self.assertNotIn("123456", text)
        self.assertNotIn("654321", text)
        self.assertNotIn("sk-synthetic", text)
        self.assertNotIn("hunter2", text)
        self.assertIn("visible", text)
        self.assertIn(REDACTED, text)

    def test_append_refuses_corrupt_tail(self):
        self.path.write_text("not json\n", encoding="utf-8")
        with self.assertRaises(LogCorruptionError):
            writer_for(self.path).append("REQUEST_RECEIVED", "req-001", {})

    def test_append_refuses_duplicate_event_id(self):
        writer = writer_for(self.path)
        writer.append("REQUEST_RECEIVED", "req-001", {}, event_id="evt-fixed")
        with self.assertRaises(ValueError):
            writer.append("REQUEST_RECEIVED", "req-002", {}, event_id="evt-fixed")
        self.assertEqual(len(read_lines(self.path)), 1)

    def test_append_refuses_earlier_tamper(self):
        build_simple_log(self.path, count=3)
        lines = read_lines(self.path)
        raw = json.loads(lines[1])
        raw["payload"]["index"] = 99
        lines[1] = canonical_json(raw)
        write_lines(self.path, lines)
        with self.assertRaises(LogCorruptionError):
            writer_for(self.path).append("REQUEST_RECEIVED", "req-001", {})

    def test_append_refuses_missing_final_newline(self):
        event = writer_for(self.path).append("REQUEST_RECEIVED", "req-001", {})
        self.path.write_text(event.to_json_line().rstrip("\n"), encoding="utf-8")
        with self.assertRaises(LogCorruptionError):
            read_last_event(self.path)

    def test_verify_empty_log(self):
        self.path.write_text("", encoding="utf-8")
        result = verify_log(self.path)
        self.assertTrue(result.valid)
        self.assertEqual(result.entries_checked, 0)
        self.assertEqual(result.errors, ())

    def test_verify_valid_log(self):
        build_simple_log(self.path, count=3)
        result = verify_log(self.path)
        self.assertTrue(result.valid)
        self.assertEqual(result.entries_checked, 3)
        self.assertEqual(result.errors, ())

    def test_verify_detects_payload_tamper(self):
        build_simple_log(self.path, count=3)
        lines = read_lines(self.path)
        raw = json.loads(lines[1])
        original_event_id = raw["event_id"]
        raw["payload"]["index"] = 99
        lines[1] = canonical_json(raw)
        write_lines(self.path, lines)
        result = verify_log(self.path)
        self.assertFalse(result.valid)
        self.assertEqual(result.first_invalid.line, 2)
        self.assertEqual(result.first_invalid.sequence, 2)
        self.assertEqual(result.first_invalid.event_id, original_event_id)
        self.assertEqual(result.first_invalid.code, "ENTRY_HASH_MISMATCH")

    def test_verify_detects_entry_hash_tamper(self):
        build_simple_log(self.path, count=3)
        lines = read_lines(self.path)
        raw = json.loads(lines[1])
        raw["entry_hash"] = "0" * 64
        lines[1] = canonical_json(raw)
        write_lines(self.path, lines)
        result = verify_log(self.path)
        self.assertFalse(result.valid)
        self.assertEqual(result.first_invalid.line, 2)
        self.assertEqual(result.first_invalid.code, "ENTRY_HASH_MISMATCH")

    def test_verify_detects_removed_middle_line(self):
        build_simple_log(self.path, count=3)
        lines = read_lines(self.path)
        del lines[1]
        write_lines(self.path, lines)
        result = verify_log(self.path)
        self.assertFalse(result.valid)
        self.assertEqual(result.first_invalid.line, 2)
        self.assertEqual(result.first_invalid.code, "SEQUENCE_MISMATCH")

    def test_verify_detects_swapped_lines(self):
        build_simple_log(self.path, count=3)
        lines = read_lines(self.path)
        lines[1], lines[2] = lines[2], lines[1]
        write_lines(self.path, lines)
        result = verify_log(self.path)
        self.assertFalse(result.valid)
        self.assertEqual(result.first_invalid.line, 2)

    def test_verify_detects_invalid_json(self):
        build_simple_log(self.path, count=3)
        lines = read_lines(self.path)
        lines[1] = "not json"
        write_lines(self.path, lines)
        result = verify_log(self.path)
        self.assertFalse(result.valid)
        self.assertEqual(result.first_invalid.line, 2)
        self.assertEqual(result.first_invalid.code, "INVALID_JSON")

    def test_verify_detects_duplicate_event_id(self):
        build_simple_log(self.path, count=2)
        lines = read_lines(self.path)
        first = json.loads(lines[0])
        second = json.loads(lines[1])
        second["event_id"] = first["event_id"]
        lines[1] = canonical_json(second)
        write_lines(self.path, lines)
        result = verify_log(self.path)
        self.assertFalse(result.valid)
        self.assertEqual(result.first_invalid.code, "DUPLICATE_EVENT_ID")

    def test_verify_detects_unknown_field(self):
        build_simple_log(self.path, count=1)
        lines = read_lines(self.path)
        raw = json.loads(lines[0])
        raw["unexpected"] = "value"
        lines[0] = canonical_json(raw)
        write_lines(self.path, lines)
        result = verify_log(self.path)
        self.assertFalse(result.valid)
        self.assertEqual(result.first_invalid.code, "UNKNOWN_FIELD")

    def test_verify_detects_missing_field(self):
        build_simple_log(self.path, count=1)
        lines = read_lines(self.path)
        raw = json.loads(lines[0])
        raw.pop("timestamp")
        lines[0] = canonical_json(raw)
        write_lines(self.path, lines)
        result = verify_log(self.path)
        self.assertFalse(result.valid)
        self.assertEqual(result.first_invalid.code, "MISSING_FIELD")

    def test_verify_detects_blank_line(self):
        build_simple_log(self.path, count=2)
        lines = read_lines(self.path)
        lines.insert(1, "")
        write_lines(self.path, lines)
        result = verify_log(self.path)
        self.assertFalse(result.valid)
        self.assertEqual(result.first_invalid.line, 2)
        self.assertEqual(result.first_invalid.code, "BLANK_LINE")

    def test_verify_detects_missing_final_newline(self):
        event = writer_for(self.path).append("REQUEST_RECEIVED", "req-001", {})
        self.path.write_text(event.to_json_line().rstrip("\n"), encoding="utf-8")
        result = verify_log(self.path)
        self.assertFalse(result.valid)
        self.assertEqual(result.first_invalid.code, "MISSING_FINAL_NEWLINE")

    def test_verify_detects_invalid_utf8(self):
        self.path.write_bytes(b"\xff\xfe")
        result = verify_log(self.path)
        self.assertFalse(result.valid)
        self.assertEqual(result.first_invalid.code, "INVALID_ENCODING")

    def test_verify_rejects_incomplete_checkpoint_even_with_valid_hash(self):
        raw = {
            "sequence": 1,
            "event_id": "evt-000001",
            "timestamp": "2026-01-01T00:00:00.000Z",
            "event_type": "CHECKPOINT_DECISION",
            "request_id": "req-001",
            "payload": {"request": {}, "signals": {}},
            "previous_hash": genesis_hash(),
        }
        raw["entry_hash"] = compute_entry_hash(raw["previous_hash"], raw)
        self.path.write_text(canonical_json(raw) + "\n", encoding="utf-8")
        result = verify_log(self.path)
        self.assertFalse(result.valid)
        self.assertEqual(result.first_invalid.code, "CHECKPOINT_CONTRACT")

    def test_checkpoint_decision_requires_replay_payload(self):
        with self.assertRaises(ValueError):
            writer_for(self.path).append(
                "CHECKPOINT_DECISION",
                "req-001",
                {"request": {}},
                decision="DENY",
                evidence_id="ev-001",
                policy_version="v1",
            )

    def test_checkpoint_decision_helper_writes_replay_payload(self):
        record = scenario_records()[0]
        decision = evaluate_policy(record["request"], record["signals"])
        event = writer_for(self.path).append_checkpoint_decision(
            record["request"], record["signals"], decision
        )
        self.assertEqual(event.event_type, "CHECKPOINT_DECISION")
        self.assertEqual(event.decision, "DENY")
        self.assertEqual(event.evidence_id, decision.evidence_id)
        self.assertEqual(event.payload["request"], record["request"].to_dict())
        self.assertEqual(event.payload["signals"], record["signals"].to_dict())

    def test_static_fixtures_are_valid(self):
        fixtures = ROOT / "tests" / "fixtures" / "logs"
        expected_entries = {"empty.jsonl": 0, "single.jsonl": 1, "multi.jsonl": 3}
        for name, count in expected_entries.items():
            result = verify_log(fixtures / name)
            self.assertTrue(result.valid, result.to_dict())
            self.assertEqual(result.entries_checked, count)

    def test_static_original_log_is_valid(self):
        result = verify_log(ROOT / "data" / "fixtures" / "original_log.jsonl")
        self.assertTrue(result.valid, result.to_dict())
        self.assertEqual(result.entries_checked, 41)

    def test_concurrent_appends_keep_chain_valid(self):
        def append_one(_: int) -> None:
            LogWriter(self.path).append(
                "REQUEST_RECEIVED",
                f"req-{uuid.uuid4().hex}",
                {"synthetic": True},
                event_id=f"evt-{uuid.uuid4().hex}",
            )

        with ThreadPoolExecutor(max_workers=8) as pool:
            list(pool.map(append_one, range(24)))

        result = verify_log(self.path)
        self.assertTrue(result.valid, result.to_dict())
        self.assertEqual(result.entries_checked, 24)
        sequences = [json.loads(line)["sequence"] for line in read_lines(self.path)]
        self.assertEqual(sequences, list(range(1, 25)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
