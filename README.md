# AI Chakravyuh - AI Tool-Call Checkpoint

AI Chakravyuh is a synthetic security checkpoint for AI-agent tool use. The
AI interprets untrusted content; deterministic policy code decides; an
append-only hash-chained log proves what happened.

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

Stdlib fallback: `python -m unittest discover -s tests -v`.

## Run the full local demo

```powershell
python -m ui.dashboard
```

Open `http://127.0.0.1:8765`. The demo uses synthetic fixtures and simulated
tools only. Run safe summary, malicious PDF and approval transfer. The
approval code is delivered through the configured mock/out-of-band adapter and
never returned by the browser endpoint.

## Run individual verification commands

```powershell
python -m ai.run_scenarios scenarios
python validate_member3.py
python -m core.verify data/fixtures/original_log.jsonl
python -m core.replay data/fixtures/original_log.jsonl --expected data/fixtures/expected_decisions.json
python scripts/demo_member1.py
python -m approval.test_flow
```

## Expected scenarios

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
