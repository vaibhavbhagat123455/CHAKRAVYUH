# Architecture

## One-sentence design

AI interprets, policy enforces, log proves.

## Module boundaries

```text
scenario fixture / real PDF inspection
      |
      v
MCP stdio client
      |
      | JSON-RPC 2.0 over stdin/stdout
      v
MCP proxy (Member 2)
      |
      +--> AI analyser (Member 3, advisory)
      |
      +--> policy matrix (core.policies, deterministic)
      |
      +--> approval service (Member 4, only for HOLD)
      |        |
      |        +--> email / Telegram / offline mock adapter
      |        +--> one-call release proof
      |
      +--> simulated tool executor
      |
      v
append-only hash-chained log (core.append_log)
      |
      +--> verify (core.verify)
      +--> replay (core.replay)
      +--> dashboard (Member 4)
```

Rules:

- every tool call passes through the checkpoint;
- every checkpoint decision is one of `ALLOW`, `HOLD`, `DENY`;
- every decision has an evidence ID;
- every event is hash-chained;
- AI output is an input signal, never the decision;
- direct tool execution that bypasses the checkpoint is unsupported.

## Seven layers

| Layer | Responsibility | Core evidence |
|---|---|---|
| DWAAR | Content trust | Prompt-injection signal |
| PEHCHAAN | Identity and scope | Request identity, purpose, scenario scope |
| SMRITI | Provenance | Scenario-bound untrusted content |
| SANKALP | Goal alignment | Goal-drift signal |
| ASTRA | Tool safety | Tool class and allowlist |
| MARYADA | Approval | HOLD and exact approval requirement |
| DRISHTI | Logging and containment | Hash-chained events and evidence IDs |

`core.layers.build_layer_results()` produces deterministic evidence for all seven even when the final result is `ALLOW`.

## Event sequence

```text
SCENARIO_START
REQUEST_RECEIVED
AI_ANALYSIS
LAYER_EVALUATED x7
CHECKPOINT_DECISION
  ALLOW -> TOOL_STARTED -> TOOL_COMPLETED
  HOLD  -> APPROVAL_CREATED -> APPROVAL_SENT -> APPROVAL_ATTEMPT/VERIFIED
  DENY  -> TOOL_BLOCKED
SCENARIO_END
```

`CHECKPOINT_DECISION` is the replay anchor. Its payload contains the exact recorded request and AI signals, so replay does not call the AI again. An `APPROVED_RELEASE` event records the final `ALLOW` outcome when a held request is later approved.

## Hash chain

Each entry stores:

- the previous entry hash, or the genesis hash for sequence 1;
- the canonical event;
- its own `entry_hash`.

Verification recomputes the hash chain and reports the exact line, sequence, event ID, expected value and actual value of the first inconsistency.

## Determinism

The following operations are deterministic:

- canonical JSON;
- policy evaluation;
- evidence IDs;
- layer results;
- decision digest.

The following are allowed only during append, never during replay:

- current time;
- UUID generation;
- network access;
- AI model calls.

## Failure behavior

| Failure | Behavior |
|---|---|
| Corrupt log tail or earlier tamper | append verifies the existing chain and refuses to extend it |
| Invalid log | replay refuses by default |
| Malformed event | verification reports `INVALID_EVENT` |
| Unknown policy version | policy fails closed |
| AI unavailable | use recorded signals for replay or conservative `HOLD` for live calls |
| Notification unavailable | fail the configured adapter; offline demo mode uses a mock adapter and explains the adapter boundary |
| UI unavailable | run the CLI verify/replay demo |

## Synthetic-only boundary

The checked-in PDFs are synthetic but real parseable PDF files. All recipients, filenames and records are synthetic. The default executor performs local PDF summarisation and writes transfer intents to an ignored sandbox directory; it never makes network side effects. Production integrations must be supplied as an explicit executor adapter and still remain behind the proxy.
