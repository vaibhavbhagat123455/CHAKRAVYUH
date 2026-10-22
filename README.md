# AI Chakravyuh - AI Tool-Call Checkpoint

AI Chakravyuh is a synthetic security checkpoint for AI-agent tool use. The
AI interprets untrusted content; deterministic policy code decides; an
append-only hash-chained log proves what happened.

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

## Run all tests

```powershell
python -m pytest -q
```

Stdlib fallback when pytest is unavailable:

```powershell
python -m unittest discover -s tests -v
```

## Run AI scenario analysis

```powershell
python -m ai.run_scenarios scenarios
python -m ai.run_scenarios scenarios/malicious_pdf.json
python validate_member3.py
```

Expected recommendations are `DENY` for the malicious PDF, `ALLOW` for the
safe summary and `HOLD` for the confidential report. AI signals are advisory;
the MCP checkpoint remains the final execution authority.

## Verify and replay the log

```powershell
python -m core.verify data/fixtures/original_log.jsonl
python -m core.replay data/fixtures/original_log.jsonl --expected data/fixtures/expected_decisions.json
python scripts/demo_member1.py
```

## Demo expectations

| Scenario | Expected decision |
|---|---|
| `malicious-pdf-001` | `DENY` |
| `safe-summary-001` | `ALLOW` |
| `approval-transfer-001` | `HOLD` |

## Team modules

- Member 1: append-only log, verification, replay and policy engine.
- Member 2: MCP JSON-RPC-over-stdio proxy and tool-call checkpoint.
- Member 3: AI threat analysis and scenario engine.
- Member 4: exact one-time approval and dashboard.

All cross-module conventions are documented in `docs/TEAM_CONTRACTS.md` and
`docs/contracts.md`.
