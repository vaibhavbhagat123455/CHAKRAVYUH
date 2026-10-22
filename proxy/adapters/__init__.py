"""Adapters package for integrating external and teammate components."""

from proxy.adapters.loader import AdapterError, load_callable

__all__ = ["AdapterError", "load_callable"]
