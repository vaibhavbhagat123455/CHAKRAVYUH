# Core: append-only evidence and deterministic policy

This package is the shared foundation for AI Chakravyuh. It has no dependency on the AI, proxy, approval or UI modules.

## Files

| File | Purpose |
|---|---|
| `contracts.py` | Frozen decisions, event types and canonical JSON |
| `canonical.py` | Genesis, SHA-256 and entry-hash formula |
| `schemas.py` | Dataclass contracts and JSON round-trips |
| `append_log.py` | `LogWriter`, redaction, full-log validation and fsync |
| `locking.py` | In-process + cross-platform advisory file lock |
| `verify.py` | Tamper-evident verification CLI |
| `replay.py` | Deterministic replay CLI |
| `policies.py` | Versioned policy matrix |
| `layers.py` | Seven-layer evidence builder |

## Hash chain

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

`previous_hash` and the canonical event are concatenated with no separator. The hash is over the event **without** `entry_hash`.

## Golden vector

These values are asserted by `tests/test_log.py` and can be reproduced by the jury:

```text
GENESIS
GENESIS_AI_CHAKRAVYUH_V1

genesis_hash
cf2aae822d95ee24ec263240279a1d80b7f7e0075e9473cb3b17b1b663f1b99e

event without entry_hash
{"event_id":"evt-000001","event_type":"REQUEST_RECEIVED","payload":{"index":1},"previous_hash":"cf2aae822d95ee24ec263240279a1d80b7f7e0075e9473cb3b17b1b663f1b99e","request_id":"req-001","sequence":1,"timestamp":"2026-01-01T00:00:00.000Z"}

entry_hash
cc022e4a676e83156fac56b4dcf5afd4348efbd24076ce8cfa8c8d76d31d9ebc
```

## Append

```python
from core.append_log import LogWriter

writer = LogWriter("data/security_log.jsonl")
event = writer.append(
    "REQUEST_RECEIVED",
    "req-001",
    {"request": {"request_id": "req-001"}},
    scenario_id="safe-summary-001",
)
```

`LogWriter`:

- opens the log in append mode only;
- locks the log while reading the tail and writing;
- uses the genesis hash for the first event;
- links every later event to the prior `entry_hash`;
- generates an event ID before hashing;
- redacts secret-bearing payload keys, including camelCase variants;
- writes exactly one JSON object plus a newline;
- flushes and calls `os.fsync`;
- verifies the whole existing log before extending it;
- rejects a duplicate explicit `event_id`;
- refuses to extend a corrupt tail, non-newline-terminated log or earlier tamper.

## Checkpoint decisions

```python
writer.append_checkpoint_decision(request, signals, decision)
```

`CHECKPOINT_DECISION` requires:

- top-level `decision`, `evidence_id` and `policy_version`;
- payload `request` and `signals`.

Replay depends on this shape.

## Verify

```powershell
python -m core.verify data/security_log.jsonl
```

The command prints JSON and exits `0` only when every event is valid. Tampering reports the exact line, sequence, event ID, expected value and actual value. Verification also enforces the replay shape of `CHECKPOINT_DECISION` events.

## Replay

```powershell
python -m core.replay data/security_log.jsonl --output replay.json
```

Replay:

- verifies the log first by default;
- reads recorded `request`, `signals` and `policy_version`;
- calls the pure `evaluate_policy` function;
- compares recorded and replayed decisions and evidence IDs;
- reports mismatches by `request_id`;
- emits a deterministic `decision_digest`;
- never calls the AI, network, clock or random generator.

Two runs over the same decisions produce the same digest even if timestamps and event IDs differ.

## Policy

```python
from core.policies import evaluate_policy

decision = evaluate_policy(request, signals, policy_version="v1")
```

The AI `recommended_action` is evidence only. It cannot override an explicit rule.

## Fixtures

```powershell
python scripts/build_member1_fixtures.py
```

This regenerates:

- `tests/fixtures/logs/empty.jsonl`
- `tests/fixtures/logs/single.jsonl`
- `tests/fixtures/logs/multi.jsonl`
- `data/fixtures/original_log.jsonl`
- `data/fixtures/expected_decisions.json`

For jury evidence:

```powershell
python scripts/demo_member1.py
```

This writes valid, tampered and replay reports to `docs/demo-evidence/`.
