# Member 1 Implementation Plan

Status: implemented and verified on `feature/log-engine`, branched from `integration`, which was created from `main`. Changes are not committed yet.

Owner: Member 1 (integration coordinator and schema owner).

## Objective

Build the shared foundation that every other module depends on:

- frozen cross-module contracts;
- append-only, hash-chained security log;
- precise tamper verification;
- deterministic replay of recorded checkpoint decisions;
- versioned policy matrix;
- seven-layer evidence records;
- tests, fixtures, documentation and CI sufficient for the jury demo.

The AI module is advisory. The log proves what happened. The deterministic checkpoint policy decides.

## Repository baseline

`main` contains the shared team foundation:

- `core/contracts.py`
- `schemas/tool_request.schema.json`
- `schemas/decision.schema.json`
- `schemas/log_event.schema.json`
- `docs/TEAM_CONTRACTS.md`
- `tests/test_shared_contracts.py`
- `pyproject.toml`
- `requirements.txt`

The AI implementation still lives on `origin/vaibhav` until it is merged into `integration`.

## Branch strategy

```powershell
git switch main
git pull --ff-only
git switch -c integration
git switch -c feature/log-engine integration
```

`feature/log-engine` opens a pull request into `integration`. After log tests pass, tag `foundation-v1`.

## Manual tasks covered

| Task | Deliverable |
|---|---|
| Integration coordinator and schema owner | Frozen contracts, changelog, merge order |
| Shared `ToolRequest` contract | `core.schemas.ToolRequest` |
| Shared `Decision` contract | `core.schemas.Decision` |
| Shared log event contract | `core.schemas.LogEvent` |
| Hash-chain design | `core/canonical.py`, golden vector in `core/README.md` |
| Append-only log | `core/append_log.py` |
| Verification | `core/verify.py` and `python -m core.verify` |
| Deterministic replay | `core/replay.py` and `python -m core.replay` |
| Policy matrix | `core/policies.py` |
| Seven-layer evidence | `core/layers.py` |
| Log tests | `tests/test_log.py` |
| Replay fixtures | `data/fixtures/original_log.jsonl` |
| Contract tests | `tests/test_contracts.py` |
| Merge first and tag | `foundation-v1` after PR approval |

## Architecture

```text
ui / approval / proxy / ai
          |
          v
        core/
          |
   +------+------+-----------+-----------+
   |             |           |           |
canonical     schemas    append_log    policies
                               |           |
                            verify       replay
                               |           |
                              layers     fixtures
```

`core/` never imports `ai/`, `proxy/`, `approval/` or `ui/`.

## Frozen contracts

- Decisions: exactly `ALLOW`, `HOLD`, `DENY`.
- Identifiers: `request_id`, `evidence_id`, `event_id`, `scenario_id`.
- JSON keys: snake_case.
- AI recommendation is recorded in `signals`, but never becomes the decision.
- `CHECKPOINT_DECISION` is the replay anchor. Its payload must contain `request` and `signals`.
- Approval event types are distinct: `APPROVAL_CREATED`, `APPROVAL_SENT`, `APPROVAL_ATTEMPT`, `APPROVAL_VERIFIED`, `APPROVAL_REJECTED`, `APPROVAL_EXPIRED`.

## Hash-chain algorithm

```text
GENESIS = "GENESIS_AI_CHAKRAVYUH_V1"
genesis_hash = SHA256(GENESIS.encode("utf-8")).hexdigest()

previous_hash = genesis_hash if sequence == 1 else prior.entry_hash

canonical_event = json.dumps(
    event_without_entry_hash,
    sort_keys=True,
    separators=(",", ":"),
    ensure_ascii=False,
    allow_nan=False,
)

entry_hash = SHA256(
    (previous_hash + canonical_event).encode("utf-8")
).hexdigest()
```

There is no delimiter between `previous_hash` and the canonical event. The canonical representation is the one already defined by `core.contracts.canonical_json`.

## Verification

`python -m core.verify data/security_log.jsonl`

Structured result includes:

- `valid`
- `entries_checked`
- `genesis`
- `first_invalid` with `line`, `sequence`, `event_id`, `code`, `expected`, `actual`
- full `errors` list

Error codes:

```text
FILE_NOT_FOUND, INVALID_ENCODING, MISSING_FINAL_NEWLINE, BLANK_LINE,
INVALID_JSON, INVALID_EVENT, MISSING_FIELD, UNKNOWN_FIELD,
SEQUENCE_MISMATCH, PREVIOUS_HASH_MISMATCH, ENTRY_HASH_MISMATCH,
DUPLICATE_EVENT_ID, CHECKPOINT_CONTRACT
```

Exit code is `0` for a valid log and `1` for an invalid log.

## Deterministic replay

`python -m core.replay data/security_log.jsonl --output replay.json`

Replay selects `CHECKPOINT_DECISION` events and re-runs `core.policies.evaluate_policy` with recorded request, signals and policy version.

It must never call the AI, current time, random numbers or the network.

Output includes:

- `valid`
- `log_verified`
- `events_replayed`
- `decision_digest`
- per-request recorded/replayed decision
- `mismatches`

Digest input:

```text
SHA256(canonical_json([
  {"request_id": ..., "decision": ..., "evidence_id": ...}
]))
```

Timestamps and event IDs are excluded, so two runs over the same decisions produce the same digest.

## Policy matrix

| Condition | Decision |
|---|---|
| Unknown tool | `DENY` |
| Injection or goal drift + sensitive/external action | `DENY` |
| Sensitive data + external destination | `HOLD` |
| Restricted tool (`send_email`, `upload_file`, `http_post`, `export_records`) | `HOLD` |
| Unsafe content for a safe tool | `HOLD` |
| Sensitive data without injection/drift | `HOLD` |
| Safe `summarize_document`, low risk | `ALLOW` |
| Unknown policy version | fail closed |

Demo expectations:

- `malicious-pdf-001` -> `DENY`
- `safe-summary-001` -> `ALLOW`
- `approval-transfer-001` -> `HOLD`

Evidence IDs are deterministic:

```text
"ev-" + SHA256(canonical_json(request, signals, policy_version, decision, matched_rule))[:16]
```

## Seven layers

`core.layers.build_layer_results()` returns deterministic evidence for:

```text
DWAAR, PEHCHAAN, SMRITI, SANKALP, ASTRA, MARYADA, DRISHTI
```

Layer statuses: `PASS`, `REVIEW`, `BLOCK`, `SKIP`.

## Test matrix

- genesis and golden hash vector
- canonical JSON stability
- empty, single and multi-entry logs
- payload tamper
- entry-hash tamper
- removed middle line
- swapped lines
- invalid JSON
- duplicate event IDs
- secret redaction, including camelCase keys
- newline-safe payload serialisation
- corrupt tail refusal
- duplicate event-ID append refusal
- earlier-tamper append refusal
- incomplete checkpoint verification refusal
- concurrent appends
- policy matrix for malicious, safe and approval scenarios
- AI `recommended_action=ALLOW` cannot override an explicit rule
- deterministic evidence IDs
- seven layer records
- replay twice with identical digest
- replay mismatch identifies `request_id`
- replay detects decision and evidence-ID changes
- replay refuses invalid logs
- replay expected-decisions file
- CLI exit codes and JSON output
- JSON schema validation
- compatibility with `ai.models.AnalysisResult`

## Conflict guards

- Do not edit `ai/`, `scenarios/`, `proxy/`, `approval/` or `ui/` in this branch.
- `core.schemas` is authoritative.
- `core.policies` is the pure policy source; Member 2 wraps it.
- Any contract change requires an update to `schemas/`, `docs/TEAM_CONTRACTS.md`, `docs/CHANGELOG.md` and tests in the same pull request.
- Never commit real data, secrets, raw approval codes or generated `data/security_log.jsonl`.

## Definition of done

```powershell
python -m pytest -q
python validate_member3.py
python -m core.verify data/fixtures/original_log.jsonl
python -m core.replay data/fixtures/original_log.jsonl --output replay.json
python -m core.replay data/fixtures/original_log.jsonl --output replay-2.json
python scripts/demo_member1.py
```

Expected:

- all tests pass offline;
- valid fixture verifies;
- tampered copy reports the exact line, sequence and event ID;
- two replay runs produce identical digests;
- a deliberate decision mismatch is reported by `request_id`;
- PR is ready for `integration` and `foundation-v1`.
