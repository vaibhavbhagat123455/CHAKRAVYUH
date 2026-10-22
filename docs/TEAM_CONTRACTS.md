# AI Chakravyuh Shared Team Contracts

All four members follow these rules. If a contract must change, open a GitHub issue first and update the schema, tests and README in the same pull request.

## Repository rules

- `main` is the stable branch.
- `integration` is the merge and end-to-end testing branch.
- Each member works on a feature branch and opens a pull request into `integration`.
- No direct tool, database or external notification call may bypass the checkpoint.
- Only synthetic data and simulated tools are allowed in the hackathon demo.

## Identifiers

- `request_id`: one tool-call attempt across all modules.
- `evidence_id`: one security decision or approval result.
- `event_id`: one immutable append-only log event.
- `scenario_id`: one repeatable fixture.

## Decision rules

Every tool request receives exactly one of `ALLOW`, `HOLD` or `DENY`.

- AI analysis recommends and explains.
- The deterministic policy checkpoint decides.
- `DENY` never invokes the executor and returns `evidence_id`.
- `HOLD` pauses only that request and requires exact, expiring approval.
- `ALLOW` is still logged before and after simulated execution.
- Evidence IDs are deterministic; do not replace them with random values.

## Log and replay contract

- Events are one JSON object per line in `data/security_log.jsonl`.
- Every event has `sequence`, `event_id`, `timestamp`, `event_type`, `request_id`, `payload`, `previous_hash` and `entry_hash`.
- `GENESIS_AI_CHAKRAVYUH_V1` is the fixed genesis string.
- `entry_hash = SHA-256(previous_hash + canonical_json(event without entry_hash))`.
- `CHECKPOINT_DECISION` is the replay anchor and must contain `request` and `signals` in its payload, plus top-level `decision`, `evidence_id` and `policy_version`.
- Replay never calls the AI, current time, random numbers or the network, and it must reproduce both the decision and the evidence ID.
- Verify with `python -m core.verify` and replay with `python -m core.replay`.
- `LogWriter` verifies the existing chain before appending, so an invalid log cannot be extended.

## Policy ownership

`core.policies.evaluate_policy` is the pure policy matrix. The Member 2 checkpoint wraps it. Do not duplicate policy rules in `proxy/` or `ui/`.

`core.policies` v1 rules:

- unknown tool -> `DENY`;
- injection or goal drift with sensitive/external action -> `DENY`;
- sensitive data with external destination -> `HOLD`;
- restricted tool -> `HOLD`;
- safe `summarize_document` with low risk -> `ALLOW`;
- unknown policy version -> fail closed.

## Approval event types

Use distinct events so the audit trail is readable:

```text
APPROVAL_CREATED, APPROVAL_SENT, APPROVAL_ATTEMPT,
APPROVAL_VERIFIED, APPROVAL_REJECTED, APPROVAL_EXPIRED
```

Never log raw approval codes.

## Integration order

1. Shared schemas and log foundation.
2. MCP proxy and deterministic checkpoint.
3. AI analysis and scenarios.
4. Approval service and dashboard.
5. End-to-end tests and jury demo.
