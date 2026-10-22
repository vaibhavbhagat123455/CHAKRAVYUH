"""Shared contracts, append-only log, policy and deterministic replay."""

from .append_log import LogWriter, append_event, read_last_event
from .canonical import GENESIS, compute_entry_hash, genesis_hash, sha256_hex
from .contracts import DECISIONS, LOG_EVENT_TYPES, POLICY_VERSION, canonical_json
from .layers import build_layer_results
from .policies import evaluate_policy
from .schemas import (
    AnalysisSignals,
    Decision,
    DecisionSignals,
    LayerResult,
    LogEvent,
    ReplayDecision,
    ReplayResult,
    ToolRequest,
    VerificationError,
    VerificationResult,
)


def __getattr__(name: str):
    """Import CLI modules lazily so python -m core.verify does not double-load them."""
    if name == "replay_log":
        from .replay import replay_log

        return replay_log
    if name == "verify_log":
        from .verify import verify_log

        return verify_log
    raise AttributeError(name)


__all__ = [
    "AnalysisSignals",
    "DECISIONS",
    "Decision",
    "DecisionSignals",
    "GENESIS",
    "LOG_EVENT_TYPES",
    "LayerResult",
    "LogEvent",
    "LogWriter",
    "POLICY_VERSION",
    "ReplayDecision",
    "ReplayResult",
    "ToolRequest",
    "VerificationError",
    "VerificationResult",
    "append_event",
    "build_layer_results",
    "canonical_json",
    "compute_entry_hash",
    "evaluate_policy",
    "genesis_hash",
    "read_last_event",
    "replay_log",
    "sha256_hex",
    "verify_log",
]
