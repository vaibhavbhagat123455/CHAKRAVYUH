# AGENTS.md

## Current repo state

- `main` contains the shared team foundation (`core/contracts.py`, `schemas/`, `docs/`, `tests/test_shared_contracts.py`, `pyproject.toml`).
- Member 1 work lives on `feature/log-engine`, branched from local `integration`, which was created from `main`. The Member 1 changes are currently uncommitted.
- The AI implementation (`ai/`, `scenarios/`, `validate_member3.py`) lives on `origin/vaibhav` and is not yet merged into `integration` or `main`.
- If expected files are missing, check `git branch -a` and `git ls-tree -r --name-only origin/vaibhav` before assuming the repo is empty.
- Target layout from the manual: `core/`, `proxy/`, `ai/`, `approval/`, `ui/`, `scenarios/`, `data/`, `tests/`, `docs/`.

## Commands

Run from the repo root:

- `python -m pytest -q` — full test suite; requires `pip install -r requirements.txt`.
- `python -m unittest tests.test_log tests.test_policy tests.test_replay tests.test_cli tests.test_contracts -v` — Member 1 stdlib fallback.
- `python -m core.verify data/fixtures/original_log.jsonl` — verify the demo log; exit 0 valid, 1 invalid.
- `python -m core.replay data/fixtures/original_log.jsonl --expected data/fixtures/expected_decisions.json` — deterministic replay.
- `python scripts/build_member1_fixtures.py` — regenerate committed Member 1 fixtures.
- `python scripts/demo_member1.py` — regenerate the tamper and replay evidence in `docs/demo-evidence/`.
- `python validate_member3.py` — Member 3 validation once `origin/vaibhav` is merged.
- `python -m ai.run_scenarios scenarios` — Member 3 scenario analyser once merged.

Use `python -m core.verify` / `python -m core.replay`, not direct file execution. `python -m pytest` uses `pythonpath = ["."]` from `pyproject.toml`.

## Contracts and conventions

- Decisions are exactly uppercase `ALLOW`, `HOLD`, `DENY`. Identifiers are `request_id`, `evidence_id`, `event_id`, `scenario_id`. Use snake_case JSON keys.
- `core/contracts.py` owns `DECISIONS`, `POLICY_VERSION`, `LOG_EVENT_TYPES` and `canonical_json`. That canonical representation is `sort_keys=True`, compact separators, `ensure_ascii=False`, `allow_nan=False`. Do not change it without updating hashes, schemas and tests.
- `core/schemas.py` is the authoritative dataclass contract. `schemas/*.schema.json` is the JSON-schema view.
- Hash chain: genesis `GENESIS_AI_CHAKRAVYUH_V1`; first `previous_hash = SHA-256(GENESIS)`; later `previous_hash = prior.entry_hash`; `entry_hash = SHA-256(previous_hash + canonical_json(event without entry_hash))`, UTF-8, no delimiter.
- `CHECKPOINT_DECISION` is the replay anchor. Its payload must contain `request` and `signals`; top-level fields are `decision`, `evidence_id`, `policy_version` and optional `analyser_version`. Replay must match both decision and evidence ID.
- `LogWriter` verifies the entire existing chain before extending it. Never bypass this check to append after a tamper.
- Approval events are distinct: `APPROVAL_CREATED`, `APPROVAL_SENT`, `APPROVAL_ATTEMPT`, `APPROVAL_VERIFIED`, `APPROVAL_REJECTED`, `APPROVAL_EXPIRED`.
- `core/policies.py` is the pure deterministic policy matrix. Member 2's checkpoint should call `evaluate_policy`; do not duplicate policy in `proxy/` or `ui/`.
- AI output is advisory only. `ai/` must adapt to `DecisionSignals`, never become the enforcement authority.
- Use synthetic fixtures only. Never add real student records, credentials, raw approval codes, or working external send/export behavior.
- `data/security_log.jsonl`, `data/*.tampered.jsonl`, `replay.json`, `.env`, `.venv` and caches are gitignored. Lock sidecars use `*.lock`.
- Any contract change must update `schemas/`, `docs/TEAM_CONTRACTS.md`, `docs/contracts.md`, `docs/CHANGELOG.md` and tests in the same pull request.

## Testing notes

- Tests are deterministic, offline and stdlib-compatible. `tests/test_contracts.py` skips AI compatibility when `ai/` is absent and JSON-schema checks when `jsonschema` is absent.
- Golden hash values are asserted in `tests/test_log.py` and documented in `core/README.md`.
- The specification is a ReportLab PDF (ASCII85 + Flate streams); if PDF reading fails, extract its text with a small Python script instead of guessing requirements.
