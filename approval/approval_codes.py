"""Atomic one-time codes bound to a canonical request digest."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Callable

from core.contracts import canonical_json as _shared_canonical_json
from .notification import MockNotificationAdapter, NotificationAdapter, mask_destination


def canonical_json(value: Any) -> str:
    # Enforce strict JSON values, then use the shared cross-module representation.
    json.dumps(value, allow_nan=False)
    return _shared_canonical_json(value)


def action_digest(request: dict[str, Any]) -> str:
    if not isinstance(request, dict) or not request.get("request_id") or not request.get("tool"):
        raise ValueError("Request must contain request_id and tool")
    if not isinstance(request.get("arguments"), dict):
        raise ValueError("Request arguments must be a JSON object")
    action = {"request_id": request["request_id"], "tool": request["tool"], "arguments": request["arguments"]}
    return hashlib.sha256(canonical_json(action).encode("utf-8")).hexdigest()


class ApprovalService:
    def __init__(self, notifier: NotificationAdapter | None = None, *, ttl_seconds: int = 180,
                 log_path: str | Path = "data/approval-events.jsonl", clock: Callable[[], float] = time.time,
                 code_factory: Callable[[], str] | None = None,
                 resume_callback: Callable[[dict[str, Any]], Any] | None = None,
                 event_sink: Callable[[dict[str, Any]], Any] | None = None) -> None:
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        self.notifier = notifier or MockNotificationAdapter()
        self.ttl_seconds, self.log_path, self.clock = ttl_seconds, Path(log_path), clock
        self.code_factory = code_factory or (lambda: f"{secrets.randbelow(1_000_000):06d}")
        self.resume_callback = resume_callback
        self.event_sink = event_sink
        self._approvals: dict[str, dict[str, Any]] = {}
        self._lock = threading.RLock()

    def _record(self, event_type: str, **fields: Any) -> None:
        event = {"event_id": f"evt-{uuid.uuid4().hex}", "timestamp": self.clock(), "event_type": event_type, **fields}
        if self.event_sink is not None:
            self.event_sink(event)
            return
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        # O_APPEND and a process lock ensure attempts are appended rather than rewritten.
        line = (canonical_json(event) + "\n").encode("utf-8")
        with self._lock, self.log_path.open("ab") as stream:
            stream.write(line)

    def create_approval(self, request: dict[str, Any], destination: str) -> dict[str, Any]:
        digest = action_digest(request)
        if not destination:
            raise ValueError("A notification destination is required")
        approval_id = f"apr-{uuid.uuid4().hex}"
        code = self.code_factory()
        if not isinstance(code, str) or len(code) < 6:
            raise ValueError("Code factory must return at least six characters")
        expires_at = self.clock() + self.ttl_seconds
        record = {"approval_id": approval_id, "request_id": request["request_id"], "action_digest": digest,
                  "code_hash": hashlib.sha256(code.encode()).hexdigest(), "expires_at": expires_at,
                  "consumed": False, "status": "PENDING", "destination": destination, "request": json.loads(canonical_json(request))}
        with self._lock:
            self._approvals[approval_id] = record
            self._record("APPROVAL_CREATED", approval_id=approval_id, request_id=request["request_id"],
                         action_digest=digest, expires_at=expires_at)
        try:
            delivery_status = self.notifier.send(destination, code, approval_id)
            with self._lock:
                record["status"] = "PENDING"
                self._record("APPROVAL_SENT", approval_id=approval_id, request_id=request["request_id"],
                             notification_status=delivery_status, destination=mask_destination(destination))
        except Exception as exc:
            with self._lock:
                record["status"] = "DELIVERY_FAILED"
                self._record("APPROVAL_REJECTED", approval_id=approval_id, request_id=request["request_id"], reason="notification_failed")
            raise RuntimeError("Approval code could not be delivered; check notification configuration") from exc
        return {"approval_id": approval_id, "request_id": request["request_id"], "status": "PENDING",
                "expires_at": expires_at, "destination": mask_destination(destination), "notification_status": delivery_status}

    def verify_approval(self, code: str, request: dict[str, Any], approval_id: str | None = None) -> dict[str, Any]:
        with self._lock:
            if approval_id is None:
                same_request = [(key, item) for key, item in self._approvals.items()
                                if item["request_id"] == request.get("request_id")]
                try:
                    digest = action_digest(request)
                    supplied_hash = hashlib.sha256(str(code).encode()).hexdigest()
                    exact = [(key, item) for key, item in same_request
                             if item["action_digest"] == digest and hmac.compare_digest(supplied_hash, item["code_hash"])]
                    matching_action = [(key, item) for key, item in same_request if item["action_digest"] == digest]
                    chosen = exact[0] if exact else (matching_action[0] if matching_action else None)
                    if chosen:
                        approval_id, record = chosen
                    else:
                        record = None
                except (ValueError, TypeError):
                    record = None
            else:
                record = self._approvals.get(approval_id)
            if record is None:
                return self._reject(approval_id, request.get("request_id"), "unknown_approval")
            if record["consumed"]:
                return self._reject(approval_id, request.get("request_id"), "code_reused")
            if self.clock() >= record["expires_at"]:
                record["status"] = "EXPIRED"
                self._record("APPROVAL_EXPIRED", approval_id=approval_id, request_id=record["request_id"])
                return self._reject(approval_id, request.get("request_id"), "code_expired")
            try:
                digest = action_digest(request)
            except (ValueError, TypeError):
                return self._reject(approval_id, request.get("request_id"), "request_mismatch")
            if not hmac.compare_digest(digest, record["action_digest"]):
                return self._reject(approval_id, request.get("request_id"), "request_mismatch")
            if not hmac.compare_digest(hashlib.sha256(str(code).encode()).hexdigest(), record["code_hash"]):
                return self._reject(approval_id, request.get("request_id"), "incorrect_code")
            # Consume while holding the lock, before invoking any release callback.
            record["consumed"], record["status"] = True, "APPROVED"
            evidence_id = f"ev-{uuid.uuid4().hex}"
            self._record("APPROVAL_VERIFIED", approval_id=approval_id, request_id=record["request_id"], evidence_id=evidence_id)
        resumed = self.resume_callback(record["request"]) if self.resume_callback else None
        return {"approved": True, "decision": "ALLOW", "approval_id": approval_id,
                "request_id": record["request_id"], "evidence_id": evidence_id, "reason": "approved_exact_action",
                "resumed": resumed}

    def _reject(self, approval_id: str | None, request_id: str | None, reason: str) -> dict[str, Any]:
        evidence_id = f"ev-{uuid.uuid4().hex}"
        self._record("APPROVAL_REJECTED", approval_id=approval_id, request_id=request_id,
                     evidence_id=evidence_id, reason=reason)
        return {"approved": False, "decision": "DENY", "approval_id": approval_id,
                "request_id": request_id, "evidence_id": evidence_id, "reason": reason}

    def expire_approval(self, approval_id: str) -> dict[str, Any]:
        with self._lock:
            record = self._approvals.get(approval_id)
            if not record:
                return {"approval_id": approval_id, "status": "NOT_FOUND"}
            if record["consumed"]:
                return {"approval_id": approval_id, "status": record["status"]}
            record["status"] = "EXPIRED"
            record["consumed"] = True
            self._record("APPROVAL_EXPIRED", approval_id=approval_id, request_id=record["request_id"])
            return {"approval_id": approval_id, "status": "EXPIRED"}

    def status(self, approval_id: str) -> dict[str, Any] | None:
        with self._lock:
            item = self._approvals.get(approval_id)
            if not item:
                return None
            status = item["status"]
            if not item["consumed"] and self.clock() >= item["expires_at"]:
                item["status"] = status = "EXPIRED"
                item["consumed"] = True
                self._record("APPROVAL_EXPIRED", approval_id=approval_id, request_id=item["request_id"])
            return {"approval_id": approval_id, "request_id": item["request_id"], "status": status,
                    "expires_at": item["expires_at"], "destination": mask_destination(item["destination"])}


_default_service = ApprovalService()


def create_approval(request: dict[str, Any], destination: str) -> dict[str, Any]:
    return _default_service.create_approval(request, destination)


def verify_approval(code: str, request: dict[str, Any], approval_id: str | None = None) -> dict[str, Any]:
    return _default_service.verify_approval(code, request, approval_id)


def expire_approval(approval_id: str) -> dict[str, Any]:
    return _default_service.expire_approval(approval_id)
