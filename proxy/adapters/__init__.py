"""Adapters package for integrating external and teammate components."""

from proxy.adapters.callables import (
    CallableAnalyser,
    CallableApproval,
    CallableLogWriter,
)
from proxy.adapters.loader import AdapterError, load_callable

__all__ = [
    "AdapterError",
    "CallableAnalyser",
    "CallableApproval",
    "CallableLogWriter",
    "load_callable",
]
