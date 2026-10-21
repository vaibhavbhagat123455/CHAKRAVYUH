# AI Chakravyuh - Member 3 AI Analysis Module

This branch contains the AI threat-analysis and repeatable synthetic scenario engine.

## Run tests

```bash
python -m pytest -q
```

The repository also has a standard-library-only validator, so the core Member
3 checks run even before pytest is installed:

```bash
python validate_member3.py
```

## Run the scenario analyser

```bash
python -m ai.run_scenarios scenarios
python -m ai.run_scenarios scenarios/malicious_pdf.json
```

Expected recommendations are `DENY` for the malicious PDF, `ALLOW` for the
safe summary and `HOLD` for the confidential report. These are advisory AI
signals; the Member 2 checkpoint remains the final execution authority.

The analyser detects indirect prompt injection, goal drift, sensitive-data risk and external destinations. It returns structured advisory signals. The MCP checkpoint must remain the final authority for ALLOW, HOLD or DENY.
