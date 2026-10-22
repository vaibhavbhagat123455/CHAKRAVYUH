# AI Chakravyuh - AI Tool-Call Checkpoint

AI Chakravyuh is a synthetic security checkpoint for AI-agent tool use. The AI interprets untrusted content; a deterministic policy checkpoint decides; an append-only hash-chained log proves what happened.

This repository currently contains the shared foundation and the Member 1 log/replay module. AI analysis, MCP proxy, approval and UI modules are integrated through the contracts in `docs/contracts.md`.

## Safety boundary

- All data, recipients, filenames and tool results are synthetic.
- The tool executor is simulated.
- No real email, database, file export or external transfer is implemented.
- Prompt-injected content is treated as untrusted data and is never executed.

## Setup

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Run tests

```powershell
python -m pytest -q
```

Stdlib fallback for the Member 1 suite:

```powershell
python -m unittest tests.test_log tests.test_policy tests.test_replay tests.test_cli tests.test_contracts -v
```

Zero-dependency fallback for the Member 3 checks once merged:

```powershell
python validate_member3.py
```

## Member 1 commands

Verify a security log:

```powershell
python -m core.verify data/security_log.jsonl
```

Replay recorded checkpoint decisions:

```powershell
python -m core.replay data/security_log.jsonl --output replay.json
```

Verify and replay the deterministic demo fixture:

```powershell
python -m core.verify data/fixtures/original_log.jsonl
python -m core.replay data/fixtures/original_log.jsonl --expected data/fixtures/expected_decisions.json
```

Regenerate all Member 1 fixtures:

```powershell
python scripts/build_member1_fixtures.py
```

Generate the tamper and replay proof for the jury:

```powershell
python scripts/demo_member1.py
```

This writes valid, tampered and replay reports to `docs/demo-evidence/`.

## Demo expectations

| Scenario | Expected decision |
|---|---|
| `malicious-pdf-001` | `DENY` |
| `safe-summary-001` | `ALLOW` |
| `approval-transfer-001` | `HOLD` |

## Useful documents

- `docs/MEMBER1_IMPLEMENTATION_PLAN.md`
- `docs/TEAM_CONTRACTS.md`
- `docs/contracts.md`
- `docs/architecture.md`
- `docs/demo-evidence/README.md`
- `core/README.md`
