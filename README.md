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

Windows shortcut:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\scripts\setup.ps1
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

Open `http://127.0.0.1:8765`. The dashboard launches a real MCP JSON-RPC
subprocess over stdin/stdout. It parses the included synthetic PDFs, runs the
checkpoint, and records every event in `data/security_log.jsonl`. The default
tool executor performs local PDF summarisation and writes transfer intents to
the ignored `data/tool-effects/` sandbox; it makes no network side effects.
`scripts/run_demo.ps1` starts with a fresh evidence log while preserving the
previous run as `security_log.jsonl.previous`.

For an actual out-of-band code delivery, copy `.env.example` to `.env`, set
`APPROVAL_CHANNEL=email` or `telegram`, and provide the corresponding SMTP or
Telegram settings. Mock mode is intentionally offline and prints the code only
to the server terminal, never to the browser.

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
