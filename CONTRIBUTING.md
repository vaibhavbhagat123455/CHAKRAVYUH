# Contributing

## Setup

```powershell
python -m venv .venv
.venv\\Scripts\\Activate.ps1
pip install -r requirements.txt
```

## Branches

Use `feature/log-engine`, `feature/mcp-proxy`, `feature/ai-analysis` or `feature/approval-ui`. Keep `main` stable and merge feature branches into `integration` through pull requests.

## Before opening a pull request

```powershell
pytest -q
git diff --check
```

Do not commit `.env`, real personal data, generated logs, `__pycache__` or a real external-exfiltration tool.
