# AI Chakravyuh - Member 3 AI Analysis Module

This branch contains the AI threat-analysis and repeatable synthetic scenario engine.

## Run tests

```bash
python -m pytest -q
```

The analyser detects indirect prompt injection, goal drift, sensitive-data risk and external destinations. It returns structured advisory signals. The MCP checkpoint must remain the final authority for ALLOW, HOLD or DENY.
