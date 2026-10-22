"""Dotted-path dynamic callable loader with clear error diagnostic messages."""

from __future__ import annotations

import importlib
from typing import Any, Callable


class AdapterError(Exception):
    """Raised when an adapter target cannot be imported or loaded."""


def load_callable(target: str) -> Callable[..., Any]:
    """Dynamically load and return a callable from a dotted path specification.

    Target format must be 'package.module:function_or_class'.
    Raises AdapterError on malformed path, missing module, or missing attribute.
    """
    if not isinstance(target, str) or not target.strip():
        raise AdapterError("Malformed dotted path: target must be a non-empty string.")

    clean_target = target.strip()
    if clean_target.count(":") != 1:
        raise AdapterError(f"Malformed dotted path '{target}': expected exactly one ':' separator (format 'module:callable').")

    module_name, attr_name = clean_target.split(":", 1)
    module_name = module_name.strip()
    attr_name = attr_name.strip()

    if not module_name or not attr_name:
        raise AdapterError(f"Malformed dotted path '{target}': module and callable attribute names cannot be empty.")

    try:
        module = importlib.import_module(module_name)
    except Exception as exc:
        raise AdapterError(f"Module '{module_name}' not found when loading '{target}': {exc}") from exc

    if not hasattr(module, attr_name):
        raise AdapterError(f"Attribute '{attr_name}' not found in module '{module_name}' when loading '{target}'.")

    callable_obj = getattr(module, attr_name)
    if not callable(callable_obj):
        raise AdapterError(f"Attribute '{attr_name}' in module '{module_name}' is not callable (type: {type(callable_obj).__name__}).")

    return callable_obj
