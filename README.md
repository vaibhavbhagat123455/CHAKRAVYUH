# AI Chakravyuh - Shared Team Foundation

This repository is the shared foundation for the final-round AI Tool-Call Checkpoint. All members must read `docs/TEAM_CONTRACTS.md` before coding.

## Setup

```powershell
python -m venv .venv
.venv\\Scripts\\Activate.ps1
pip install -r requirements.txt
```

## Run tests

```powershell
pytest -q
```

The `main` branch contains shared contracts and schemas. Member branches add their modules. AI analysis returns structured advisory signals; the MCP checkpoint remains the final authority for ALLOW, HOLD or DENY.

## Member 4: approval dashboard and demo

See [docs/MEMBER4.md](docs/MEMBER4.md) for the one-time approval service, local dashboard, notification setup, and demo commands.
