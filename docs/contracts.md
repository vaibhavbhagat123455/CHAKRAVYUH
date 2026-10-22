# Cross-module contracts

This document is the integration contract for Members 1-4. `core.schemas` is the executable source of truth; `schemas/*.schema.json` provides the JSON-schema view.

If a field changes, update the schema, tests, this document, `docs/TEAM_CONTRACTS.md` and `docs/CHANGELOG.md` in the same pull request.

## `ToolRequest`

```json
{
  "request_id": "req-malicious-001",
  "tool": "send_email",
  "arguments": {
    "recipient": "external@example.com",
    "file": "synthetic_student_records.pdf"
  },
  "purpose": "Send student records outside the organisation",
  "scenario_id": "malicious-pdf-001"
}
```

Rules:

- all five fields are required;
- `arguments` is a JSON object;
- `request_id` is stable across every event for one attempt;
- `scenario_id` must equal the scenario fixture ID;
- use synthetic recipients, filenames and data only.

`ToolRequest.fingerprint()` returns a SHA-256 hash of the canonical request. Any argument change changes the fingerprint.

## `DecisionSignals`

This is the adapter boundary between the AI module and policy.

```json
{
  "prompt_injection": true,
  "goal_drift": true,
  "sensitive_data_risk": "high",
  "risk_score": 0.96,
  "recommended_action": "DENY",
  "reason": "The content attempts to change the authorised task.",
  "evidence": ["prompt-injection pattern: ignore previous instructions"],
  "analyser_version": "rules-v1"
}
```

Rules:

- `sensitive_data_risk` is `low`, `medium` or `high`;
- `risk_score` is between 0 and 1;
- `recommended_action` is advisory;
- `analyser_version` must be recorded in the log;
- `core.schemas.DecisionSignals.from_mapping(ai_result.to_dict())` accepts the existing Member 3 output.

## `Decision`

```json
{
  "request_id": "req-malicious-001",
  "decision": "DENY",
  "evidence_id": "ev-...",
  "reason": "The content attempts to change the authorised task while moving sensitive data or reaching an external destination.",
  "policy_version": "v1",
  "signals": {
    "prompt_injection": true,
    "goal_drift": true,
    "sensitive_data_risk": "high",
    "risk_score": 0.96,
    "recommended_action": "DENY",
    "reason": "The content attempts to change the authorised task.",
    "evidence": ["prompt-injection pattern: ignore previous instructions"],
    "analyser_version": "rules-v1"
  },
  "policy_facts": {
    "matched_rule": "injection_or_drift_with_sensitive_or_external",
    "tool": "send_email",
    "tool_class": "approval",
    "prompt_injection": true,
    "goal_drift": true,
    "sensitive_data": true,
    "external_destination": true
  },
  "layer_results": []
}
```

Rules:

- `evidence_id` is required for `ALLOW`, `HOLD` and `DENY`;
- `evidence_id` is deterministic for the same request, signals, policy version and rule;
- `policy_facts` is structured; `reason` is human-readable;
- AI free-form text never replaces the `decision` field.

## `LayerResult`

```json
{
  "layer_id": "DWAAR",
  "status": "BLOCK",
  "reason": "untrusted content contains instruction-override patterns",
  "evidence_id": "ev-..."
}
```

Layer IDs:

```text
DWAAR, PEHCHAAN, SMRITI, SANKALP, ASTRA, MARYADA, DRISHTI
```

Statuses:

```text
PASS, REVIEW, BLOCK, SKIP
```

## `LogEvent`

```json
{
  "sequence": 12,
  "event_id": "evt-000012",
  "timestamp": "2026-01-01T00:00:11.000Z",
  "event_type": "CHECKPOINT_DECISION",
  "request_id": "req-malicious-001",
  "scenario_id": "malicious-pdf-001",
  "decision": "DENY",
  "evidence_id": "ev-...",
  "policy_version": "v1",
  "analyser_version": "rules-v1",
  "payload": {
    "request": {},
    "signals": {}
  },
  "previous_hash": "...",
  "entry_hash": "..."
}
```

Required fields:

```text
sequence, event_id, timestamp, event_type, request_id, payload,
previous_hash, entry_hash
```

Optional top-level fields:

```text
scenario_id, decision, evidence_id, policy_version, analyser_version
```

Hashes are lowercase 64-character SHA-256 hex digests. Timestamps are ISO-8601 UTC with a `Z` suffix.

## Event types

```text
SCENARIO_START
REQUEST_RECEIVED
AI_ANALYSIS
LAYER_EVALUATED
CHECKPOINT_DECISION
APPROVAL_CREATED
APPROVAL_SENT
APPROVAL_ATTEMPT
APPROVAL_VERIFIED
APPROVAL_REJECTED
APPROVAL_EXPIRED
TOOL_STARTED
TOOL_COMPLETED
TOOL_BLOCKED
TOOL_TIMEOUT
CONTAINMENT
SCENARIO_END
```

Approval events are deliberately distinct so the UI and jury can show exactly which approval step happened.

## Event payloads

| Event | Required payload |
|---|---|
| `SCENARIO_START` | `scenario_id`, optional display name |
| `REQUEST_RECEIVED` | `request` |
| `AI_ANALYSIS` | `signals` |
| `LAYER_EVALUATED` | `layer` |
| `CHECKPOINT_DECISION` | `request`, `signals`; top-level `decision`, `evidence_id`, `policy_version` |
| `APPROVAL_CREATED` | `approval_id`, `action_digest` |
| `APPROVAL_SENT` | `approval_id`, masked destination |
| `APPROVAL_ATTEMPT` | `approval_id`, outcome status |
| `APPROVAL_VERIFIED` | `approval_id`, evidence ID |
| `APPROVAL_REJECTED` | `approval_id`, reason |
| `APPROVAL_EXPIRED` | `approval_id` |
| `TOOL_STARTED` | `tool` |
| `TOOL_COMPLETED` | `tool`, simulated result summary |
| `TOOL_BLOCKED` | `tool`, `evidence_id` |
| `TOOL_TIMEOUT` | `tool`, timeout reason |
| `CONTAINMENT` | containment action and evidence |
| `SCENARIO_END` | final decision and evidence ID |

Never log raw approval codes, passwords, tokens or real personal data. `LogWriter` redacts secret-bearing keys, but callers must still avoid putting them in payloads.

## Replay contract

`core.replay` selects only `CHECKPOINT_DECISION` events and re-runs the deterministic policy.

The log must contain:

```json
{
  "event_type": "CHECKPOINT_DECISION",
  "decision": "DENY",
  "evidence_id": "ev-...",
  "policy_version": "v1",
  "payload": {
    "request": {},
    "signals": {}
  }
}
```

Replay re-evaluates the policy and requires both the recorded decision and the recorded evidence ID to match. Verification rejects a checkpoint that is missing any replay field even when its hash chain is otherwise intact.

Replay output includes a deterministic digest:

```text
SHA256(canonical_json([
  {"request_id": ..., "decision": ..., "evidence_id": ...}
]))
```

Do not include timestamps, event IDs, line numbers or current time in the digest.

## Policy matrix v1

| Condition | Decision |
|---|---|
| Unknown tool | `DENY` |
| Injection or goal drift + sensitive/external action | `DENY` |
| Sensitive data + external destination | `HOLD` |
| Restricted tool | `HOLD` |
| Unsafe content for a safe tool | `HOLD` |
| Sensitive data without injection/drift | `HOLD` |
| Safe `summarize_document`, low risk | `ALLOW` |
| Unknown policy version | fail closed |

Demo expectations:

```text
malicious-pdf-001     -> DENY
safe-summary-001      -> ALLOW
approval-transfer-001 -> HOLD
```

## Ownership

| Module | Owner | Contract usage |
|---|---|---|
| `core/schemas.py` | Member 1 | authoritative |
| `core/append_log.py` | Member 1 | Member 2/4 write events |
| `core/verify.py` | Member 1 | CLI and UI verify action |
| `core/replay.py` | Member 1 | CLI and UI replay action |
| `core/policies.py` | Member 1 | Member 2 checkpoint calls it |
| `core/layers.py` | Member 1 | Member 4 renders results |
| `ai/` | Member 3 | adapts `AnalysisResult` to `DecisionSignals` |
| `proxy/` | Member 2 | wraps policy and log |
| `approval/`, `ui/` | Member 4 | consumes decisions and evidence IDs |
