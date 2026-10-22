"""Small, dependency-free configuration helpers shared by every process."""

from __future__ import annotations

import os
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_dotenv(path: str | Path | None = None) -> None:
    """Load simple KEY=VALUE settings without overriding real environment values."""
    dotenv = Path(path) if path is not None else ROOT / ".env"
    if not dotenv.is_file():
        return
    for raw_line in dotenv.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip().strip("\"'")
        if key and key not in os.environ:
            os.environ[key] = value


def configured_log_path(default: str | Path | None = None) -> Path:
    """Return the one canonical append-only log path for the current process."""
    if default is not None:
        return Path(default)
    configured = os.getenv("LOG_PATH")
    if configured:
        return Path(configured)
    return Path(default or ROOT / "data" / "security_log.jsonl")


def configured_approval_ttl(default: int = 300) -> int:
    raw = os.getenv("APPROVAL_CODE_TTL_SECONDS", str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError("APPROVAL_CODE_TTL_SECONDS must be an integer") from exc
    if value <= 0:
        raise ValueError("APPROVAL_CODE_TTL_SECONDS must be positive")
    return value


__all__ = ["ROOT", "configured_approval_ttl", "configured_log_path", "load_dotenv"]
