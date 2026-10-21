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

## Integration order

1. Shared schemas and log foundation.
2. MCP proxy and deterministic checkpoint.
3. AI analysis and scenarios.
4. Approval service and dashboard.
5. End-to-end tests and jury demo.
