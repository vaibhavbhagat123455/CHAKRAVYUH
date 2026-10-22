import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from core.contracts import canonical_json
from tests.log_helpers import build_demo_log, build_simple_log, read_lines, scenario_records, write_lines

ROOT = Path(__file__).parents[1]


def run_module(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.root = Path(self.tempdir.name)

    def test_verify_cli_valid_log(self):
        path = self.root / "security_log.jsonl"
        build_simple_log(path, count=2)
        result = run_module("-m", "core.verify", str(path))
        self.assertEqual(result.returncode, 0, result.stderr)
        payload = json.loads(result.stdout)
        self.assertTrue(payload["valid"])
        self.assertEqual(payload["entries_checked"], 2)

    def test_verify_cli_invalid_log_exits_nonzero(self):
        path = self.root / "security_log.jsonl"
        build_simple_log(path, count=2)
        lines = read_lines(path)
        raw = json.loads(lines[1])
        raw["payload"]["index"] = 999
        lines[1] = canonical_json(raw)
        write_lines(path, lines)
        result = run_module("-m", "core.verify", str(path))
        self.assertEqual(result.returncode, 1)
        payload = json.loads(result.stdout)
        self.assertFalse(payload["valid"])
        self.assertEqual(payload["first_invalid"]["line"], 2)
        self.assertEqual(payload["first_invalid"]["code"], "ENTRY_HASH_MISMATCH")

    def test_replay_cli_valid_log_writes_output(self):
        path = self.root / "security_log.jsonl"
        output = self.root / "replay.json"
        build_demo_log(path)
        result = run_module("-m", "core.replay", str(path), "--output", str(output))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(output.exists())
        payload = json.loads(output.read_text(encoding="utf-8"))
        self.assertTrue(payload["valid"])
        self.assertEqual(payload["events_replayed"], 3)
        self.assertTrue(payload["decision_digest"].startswith("sha256:"))

    def test_replay_cli_mismatch_exits_nonzero(self):
        path = self.root / "security_log.jsonl"
        expected = self.root / "expected_decisions.json"
        build_demo_log(path)
        expected.write_text(json.dumps({"req-malicious-001": "ALLOW"}), encoding="utf-8")
        result = run_module("-m", "core.replay", str(path), "--expected", str(expected))
        self.assertEqual(result.returncode, 1)
        payload = json.loads(result.stdout)
        self.assertFalse(payload["valid"])
        self.assertTrue(payload["mismatches"])

    def test_replay_cli_expected_file_matches(self):
        path = self.root / "security_log.jsonl"
        expected = self.root / "expected_decisions.json"
        build_demo_log(path)
        expected.write_text(
            json.dumps({record["request"].request_id: record["expected"] for record in scenario_records()}),
            encoding="utf-8",
        )
        result = run_module("-m", "core.replay", str(path), "--expected", str(expected))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)["valid"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
