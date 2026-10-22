import json
import tempfile
import unittest
from pathlib import Path

from core.contracts import canonical_json
from core.replay import replay_log
from tests.log_helpers import (
    build_demo_log,
    build_simple_log,
    read_lines,
    scenario_records,
    write_lines,
)

ROOT = Path(__file__).parents[1]


class ReplayTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.root = Path(self.tempdir.name)
        self.path = self.root / "security_log.jsonl"

    def test_static_original_fixture_replays(self):
        result = replay_log(
            ROOT / "data" / "fixtures" / "original_log.jsonl",
            expected=ROOT / "data" / "fixtures" / "expected_decisions.json",
        )
        self.assertTrue(result.valid, result.to_dict())
        self.assertEqual(result.events_replayed, 3)
        self.assertEqual(
            result.decision_digest,
            "sha256:a8a98ac5ca57c9428a3b2139ad55e4867bd3d1feb8f36b676ba37c5879793da5",
        )

    def test_replay_matches_recorded_decisions(self):
        build_demo_log(self.path)
        result = replay_log(self.path)
        self.assertTrue(result.valid, result.to_dict())
        self.assertTrue(result.log_verified)
        self.assertEqual(result.events_replayed, 3)
        self.assertEqual(result.mismatches, ())
        self.assertTrue(result.decision_digest.startswith("sha256:"))
        self.assertEqual(
            {decision.request_id: decision.replayed for decision in result.decisions},
            {
                "req-malicious-001": "DENY",
                "req-safe-001": "ALLOW",
                "req-approval-001": "HOLD",
            },
        )

    def test_replay_twice_produces_identical_digest(self):
        build_demo_log(self.path)
        first = replay_log(self.path)
        second = replay_log(self.path)
        self.assertEqual(first.decision_digest, second.decision_digest)

    def test_replay_digest_ignores_timestamps_and_event_ids(self):
        other = self.root / "other_log.jsonl"
        build_demo_log(self.path, start="2026-01-01T00:00:00.000Z", prefix="evt-a")
        build_demo_log(other, start="2030-06-01T12:00:00.000Z", prefix="evt-b")
        first = replay_log(self.path)
        second = replay_log(other)
        self.assertEqual(first.decision_digest, second.decision_digest)

    def test_replay_expected_file(self):
        build_demo_log(self.path)
        expected = self.root / "expected_decisions.json"
        expected.write_text(
            json.dumps({record["request"].request_id: record["expected"] for record in scenario_records()}),
            encoding="utf-8",
        )
        result = replay_log(self.path, expected=expected)
        self.assertTrue(result.valid, result.to_dict())

    def test_replay_expected_mismatch_is_reported(self):
        build_demo_log(self.path)
        expected = self.root / "expected_decisions.json"
        expected.write_text(json.dumps({"req-malicious-001": "ALLOW"}), encoding="utf-8")
        result = replay_log(self.path, expected=expected)
        self.assertFalse(result.valid)
        self.assertTrue(result.mismatches)
        mismatch = result.mismatches[0]
        self.assertEqual(mismatch.request_id, "req-malicious-001")
        self.assertEqual(mismatch.expected, "ALLOW")

    def test_replay_refuses_invalid_log(self):
        build_simple_log(self.path, count=2)
        lines = read_lines(self.path)
        raw = json.loads(lines[0])
        raw["entry_hash"] = "0" * 64
        lines[0] = canonical_json(raw)
        write_lines(self.path, lines)
        result = replay_log(self.path)
        self.assertFalse(result.valid)
        self.assertFalse(result.log_verified)
        self.assertIn("failed verification", result.error or "")

    def test_replay_detects_recorded_decision_change_without_verify(self):
        build_demo_log(self.path)
        lines = read_lines(self.path)
        for index, line in enumerate(lines):
            raw = json.loads(line)
            if raw["event_type"] == "CHECKPOINT_DECISION" and raw["request_id"] == "req-malicious-001":
                raw["decision"] = "ALLOW"
                lines[index] = canonical_json(raw)
                break
        else:
            self.fail("malicious checkpoint event not found")
        write_lines(self.path, lines)
        result = replay_log(self.path, verify=False)
        self.assertFalse(result.valid)
        self.assertFalse(result.log_verified)
        mismatch = result.mismatches[0]
        self.assertEqual(mismatch.request_id, "req-malicious-001")
        self.assertEqual(mismatch.recorded, "ALLOW")
        self.assertEqual(mismatch.replayed, "DENY")

    def test_replay_detects_recorded_evidence_id_change_without_verify(self):
        build_demo_log(self.path)
        lines = read_lines(self.path)
        for index, line in enumerate(lines):
            raw = json.loads(line)
            if raw["event_type"] == "CHECKPOINT_DECISION":
                raw["evidence_id"] = "ev-tampered"
                lines[index] = canonical_json(raw)
                break
        else:
            self.fail("checkpoint event not found")
        write_lines(self.path, lines)
        result = replay_log(self.path, verify=False)
        self.assertFalse(result.valid)
        self.assertFalse(result.log_verified)
        self.assertFalse(result.mismatches[0].evidence_id_match)

    def test_replay_rejects_checkpoint_without_evidence_id(self):
        build_demo_log(self.path)
        lines = read_lines(self.path)
        for index, line in enumerate(lines):
            raw = json.loads(line)
            if raw["event_type"] == "CHECKPOINT_DECISION":
                raw.pop("evidence_id")
                lines[index] = canonical_json(raw)
                break
        else:
            self.fail("checkpoint event not found")
        write_lines(self.path, lines)
        result = replay_log(self.path, verify=False)
        self.assertFalse(result.valid)
        self.assertIn("evidence_id", result.error or "")

    def test_replay_rejects_checkpoint_without_signals(self):
        build_demo_log(self.path)
        lines = read_lines(self.path)
        for index, line in enumerate(lines):
            raw = json.loads(line)
            if raw["event_type"] == "CHECKPOINT_DECISION":
                raw["payload"].pop("signals")
                lines[index] = canonical_json(raw)
                break
        else:
            self.fail("checkpoint event not found")
        write_lines(self.path, lines)
        result = replay_log(self.path, verify=False)
        self.assertFalse(result.valid)
        self.assertIn("request and signals", result.error or "")

    def test_replay_empty_log_is_valid(self):
        self.path.write_text("", encoding="utf-8")
        result = replay_log(self.path)
        self.assertTrue(result.valid)
        self.assertEqual(result.events_replayed, 0)

    def test_replay_expected_missing_from_log_is_invalid(self):
        build_demo_log(self.path)
        expected = self.root / "expected_decisions.json"
        expected.write_text(json.dumps({"req-missing": "DENY"}), encoding="utf-8")
        result = replay_log(self.path, expected=expected)
        self.assertFalse(result.valid)
        self.assertIn("missing from the log", result.error or "")


if __name__ == "__main__":
    unittest.main(verbosity=2)
