"""Generate the Member 1 tamper/replay evidence used in the jury demo.

Run from the repository root:

    python scripts/demo_member1.py
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.contracts import canonical_json
from core.replay import replay_log
from core.verify import verify_log
from tests.log_helpers import build_demo_log, read_lines, write_lines


def _write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _write_verification(path: Path, result) -> None:
    data = result.to_dict()
    data["log_path"] = Path(data["log_path"]).as_posix()
    _write_json(path, data)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate Member 1 demo evidence")
    parser.add_argument(
        "--output-dir",
        default="docs/demo-evidence",
        help="directory for generated evidence, relative to the repository root",
    )
    args = parser.parse_args()
    output = Path(args.output_dir)
    output.mkdir(parents=True, exist_ok=True)

    original = output / "original_log.jsonl"
    tampered = output / "tampered_log.jsonl"
    for path in (original, tampered):
        path.unlink(missing_ok=True)
    build_demo_log(original)

    original_result = verify_log(original)
    _write_verification(output / "verify_original.json", original_result)
    if not original_result.valid:
        raise SystemExit(f"original fixture failed verification: {original_result.to_dict()}")

    shutil.copyfile(original, tampered)
    lines = read_lines(tampered)
    changed = False
    for index, line in enumerate(lines):
        raw = json.loads(line)
        if raw["event_type"] == "REQUEST_RECEIVED":
            raw["payload"]["tampered"] = True
            lines[index] = canonical_json(raw)
            changed = True
            break
    if not changed:
        raise SystemExit("no REQUEST_RECEIVED event found to tamper with")
    write_lines(tampered, lines)
    tampered_result = verify_log(tampered)
    _write_verification(output / "verify_tampered.json", tampered_result)
    if tampered_result.valid:
        raise SystemExit("tampered fixture unexpectedly verified as valid")

    first = replay_log(original, expected=ROOT / "data" / "fixtures" / "expected_decisions.json")
    second = replay_log(original, expected=ROOT / "data" / "fixtures" / "expected_decisions.json")
    _write_json(output / "replay_1.json", first.to_dict())
    _write_json(output / "replay_2.json", second.to_dict())
    if not first.valid or not second.valid:
        raise SystemExit("replay failed")
    if first.decision_digest != second.decision_digest:
        raise SystemExit("replay digests differ")

    summary = {
        "original_valid": original_result.valid,
        "original_entries": original_result.entries_checked,
        "tampered_valid": tampered_result.valid,
        "tampered_first_invalid": tampered_result.first_invalid.to_dict() if tampered_result.first_invalid else None,
        "replay_valid": first.valid,
        "replay_events": first.events_replayed,
        "decision_digest": first.decision_digest,
        "replay_digests_match": first.decision_digest == second.decision_digest,
    }
    _write_json(output / "summary.json", summary)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
