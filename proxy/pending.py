"""Store and lifecycle management for pending HOLD requests."""

from __future__ import annotations

from dataclasses import dataclass
import threading
import time
from typing import Dict, List, Optional

from proxy.canonical import action_digest
from proxy.config import ProxyConfig
from proxy.interfaces import Clock
from proxy.models import DecisionSignals, ToolRequest


@dataclass(frozen=True)
class PendingRecord:
    """Frozen state record for an intercepted tool request placed on HOLD."""

    request: ToolRequest
    action_digest: str
    evidence_id: str
    signals: Optional[DecisionSignals]
    created_at: float
    expires_at: float
    approval_id: str


class PendingStore:
    """Thread-safe store for pending requests requiring out-of-band authorization."""

    def __init__(
        self,
        clock: Optional[Clock] = None,
        hold_ttl_seconds: Optional[int] = None,
    ) -> None:
        self.clock = clock
        if hold_ttl_seconds is None:
            hold_ttl_seconds = ProxyConfig().hold_ttl_seconds
        self.hold_ttl_seconds = float(hold_ttl_seconds)
        self._records: Dict[str, PendingRecord] = {}
        self._lock = threading.Lock()

    def _now(self) -> float:
        return self.clock.now() if self.clock is not None else time.time()

    def add(
        self,
        request: ToolRequest,
        evidence_id: str,
        signals: Optional[DecisionSignals],
        approval_id: str,
    ) -> PendingRecord:
        """Create and store a PendingRecord calculated against clock and hold_ttl."""
        now = self._now()
        digest = action_digest(request.tool, request.arguments)
        record = PendingRecord(
            request=request,
            action_digest=digest,
            evidence_id=evidence_id,
            signals=signals,
            created_at=now,
            expires_at=now + self.hold_ttl_seconds,
            approval_id=approval_id,
        )
        with self._lock:
            self._records[request.request_id] = record
        return record

    def get(self, request_id: str) -> Optional[PendingRecord]:
        """Fetch pending record by request_id."""
        with self._lock:
            return self._records.get(request_id)

    def remove(self, request_id: str) -> Optional[PendingRecord]:
        """Remove and return pending record by request_id."""
        with self._lock:
            return self._records.pop(request_id, None)

    def list_all(self) -> List[PendingRecord]:
        """List snapshot of all currently stored pending records."""
        with self._lock:
            return list(self._records.values())
