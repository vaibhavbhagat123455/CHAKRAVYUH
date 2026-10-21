"""Central configuration module for AI Chakravyuh proxy."""

from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Mapping, Optional


@dataclass(frozen=True)
class ProxyConfig:
    """Frozen configuration settings for proxy and checkpoint runtime."""

    tool_timeout_seconds: float = 5.0
    hold_ttl_seconds: int = 120
    policy_file: Optional[str] = None

    def __post_init__(self) -> None:
        if not isinstance(self.tool_timeout_seconds, (int, float)) or self.tool_timeout_seconds <= 0:
            raise ValueError(f"tool_timeout_seconds must be a positive number, got: {self.tool_timeout_seconds!r}")
        if not isinstance(self.hold_ttl_seconds, (int, float)) or self.hold_ttl_seconds <= 0:
            raise ValueError(f"hold_ttl_seconds must be a positive number, got: {self.hold_ttl_seconds!r}")
        if self.policy_file is not None and (not isinstance(self.policy_file, str) or not self.policy_file.strip()):
            raise ValueError(f"policy_file must be None or a non-empty string, got: {self.policy_file!r}")

    @classmethod
    def from_env(cls, environ: Optional[Mapping[str, str]] = None) -> ProxyConfig:
        """Create ProxyConfig from environment mapping, using defaults if unset."""
        env = os.environ if environ is None else environ

        # 1. tool_timeout_seconds
        timeout_val: float = 5.0
        if "CHAKRAVYUH_TOOL_TIMEOUT" in env:
            raw_timeout = env["CHAKRAVYUH_TOOL_TIMEOUT"].strip()
            try:
                timeout_val = float(raw_timeout)
            except ValueError:
                raise ValueError(f"CHAKRAVYUH_TOOL_TIMEOUT must be a valid float, got: {raw_timeout!r}")

        # 2. hold_ttl_seconds
        ttl_val: int = 120
        if "CHAKRAVYUH_HOLD_TTL" in env:
            raw_ttl = env["CHAKRAVYUH_HOLD_TTL"].strip()
            try:
                ttl_val = int(raw_ttl)
            except ValueError:
                raise ValueError(f"CHAKRAVYUH_HOLD_TTL must be a valid integer, got: {raw_ttl!r}")

        # 3. policy_file
        policy_file_val: Optional[str] = None
        if "CHAKRAVYUH_POLICY_FILE" in env:
            raw_policy = env["CHAKRAVYUH_POLICY_FILE"].strip()
            if raw_policy:
                policy_file_val = raw_policy

        return cls(
            tool_timeout_seconds=timeout_val,
            hold_ttl_seconds=ttl_val,
            policy_file=policy_file_val,
        )
