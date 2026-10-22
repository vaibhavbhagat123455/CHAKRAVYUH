"""Regenerate deterministic Member 1 fixtures.

Run from the repository root:

    python scripts/build_member1_fixtures.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.replay import replay_log
from core.verify import verify_log
from tests.log_helpers import build_demo_log, build_simple_log, scenario_records


def main() -> int:
    log_fixtures = ROOT / "tests" / "fixtures" / "logs"
    data_fixtures = ROOT / "data" / "fixtures"
    log_fixtures.mkdir(parents=True, exist_ok=True)
    data_fixtures.mkdir(parents=True, exist_ok=True)

    empty = log_fixtures / "empty.jsonl"
    single = log_fixtures / "single.jsonl"
    multi = log_fixtures / "multi.jsonl"
    original = data_fixtures / "original_log.jsonl"
    for path in (empty, single, multi, original):
        path.unlink(missing_ok=True)

    empty.write_text("", encoding="utf-8")
    build_simple_log(single, count=1, prefix="single")
    build_simple_log(multi, count=3, prefix="multi")
    build_demo_log(original)
    expected = {
        record["request"].request_id: record["expected"]
        for record in scenario_records()
    }
    expected_path = data_fixtures / "expected_decisions.json"
    expected_path.write_text(json.dumps(expected, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    verification = verify_log(original)
    if not verification.valid:
        raise SystemExit(f"generated log failed verification: {verification.to_dict()}")
    replay = replay_log(original, expected=expected_path)
    if not replay.valid:
        raise SystemExit(f"generated log failed replay: {replay.to_dict()}")

    print(f"wrote {len(verification.errors)} verification errors")
    print(f"entries_checked={verification.entries_checked}")
    print(f"events_replayed={replay.events_replayed}")
    print(f"decision_digest={replay.decision_digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
