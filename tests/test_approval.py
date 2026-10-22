from __future__ import annotations

import json
import threading
from pathlib import Path

from approval.approval_codes import ApprovalService
from approval.notification import MockNotificationAdapter


def request(**overrides):
    result = {"request_id": "req-001", "tool": "send_email", "arguments": {"recipient": "reviewer@example.test"}, "scenario_id": "synthetic-1"}
    result.update(overrides)
    return result


def make_service(tmp_path, *, now=None, ttl=60, resume=None):
    current = [1000.0 if now is None else now]
    notifier = MockNotificationAdapter()
    service = ApprovalService(notifier, ttl_seconds=ttl, log_path=tmp_path / "approval.jsonl",
                              clock=lambda: current[0], code_factory=lambda: "123456", resume_callback=resume)
    return service, notifier, current


def create(service, notifier, req=None):
    approval = service.create_approval(req or request(), "reviewer@example.test")
    return approval, notifier.deliveries[-1]["code"]


def test_correct_code_approves_exact_action_once(tmp_path):
    resumed = []
    service, notifier, _ = make_service(tmp_path, resume=lambda req: resumed.append(req["request_id"]) or "released")
    approval, code = create(service, notifier)
    result = service.verify_approval(code, request())
    assert result["approved"] and result["decision"] == "ALLOW"
    assert result["evidence_id"].startswith("ev-") and result["resumed"] == "released"
    assert resumed == ["req-001"]


def test_wrong_code_is_denied(tmp_path):
    service, notifier, _ = make_service(tmp_path)
    approval, _ = create(service, notifier)
    assert service.verify_approval("999999", request(), approval["approval_id"])["reason"] == "incorrect_code"


def test_expired_code_is_denied_and_logged(tmp_path):
    service, notifier, now = make_service(tmp_path, ttl=10)
    approval, code = create(service, notifier)
    now[0] += 10
    assert service.verify_approval(code, request(), approval["approval_id"])["reason"] == "code_expired"


def test_reused_code_is_denied(tmp_path):
    service, notifier, _ = make_service(tmp_path)
    approval, code = create(service, notifier)
    assert service.verify_approval(code, request(), approval["approval_id"])["approved"]
    assert service.verify_approval(code, request(), approval["approval_id"])["reason"] == "code_reused"


def test_code_cannot_approve_another_tool_or_request(tmp_path):
    service, notifier, _ = make_service(tmp_path)
    approval, code = create(service, notifier)
    altered = {**request(), "tool": "delete_file"}
    assert service.verify_approval(code, altered, approval["approval_id"])["reason"] == "request_mismatch"


def test_code_cannot_approve_modified_arguments(tmp_path):
    service, notifier, _ = make_service(tmp_path)
    approval, code = create(service, notifier)
    altered = request(arguments={"recipient": "attacker@example.test"})
    assert service.verify_approval(code, altered, approval["approval_id"])["reason"] == "request_mismatch"


def test_held_request_resumes_after_valid_approval(tmp_path):
    released = []
    service, notifier, _ = make_service(tmp_path, resume=lambda req: released.append(req) or "resumed")
    approval, code = create(service, notifier)
    assert service.verify_approval(code, request(), approval["approval_id"])["resumed"] == "resumed"
    assert released == [request()]


def test_other_independent_requests_continue_while_held(tmp_path):
    service, notifier, _ = make_service(tmp_path)
    approval, _ = create(service, notifier)
    safe = request(request_id="req-safe", tool="summarize_document")
    safe_approval, safe_code = create(service, notifier, safe)
    assert service.verify_approval(safe_code, safe, safe_approval["approval_id"])["approved"]
    assert service.status(approval["approval_id"])["status"] == "PENDING"
    assert safe["request_id"] != approval["request_id"]


def test_every_approval_attempt_is_appended_without_code(tmp_path):
    service, notifier, _ = make_service(tmp_path)
    approval, code = create(service, notifier)
    service.verify_approval("999999", request(), approval["approval_id"])
    service.verify_approval(code, request(), approval["approval_id"])
    service.verify_approval(code, request(), approval["approval_id"])
    path = tmp_path / "approval.jsonl"
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    assert [row["event_type"] for row in rows] == ["APPROVAL_CREATED", "APPROVAL_SENT", "APPROVAL_REJECTED", "APPROVAL_VERIFIED", "APPROVAL_REJECTED"]
    assert "123456" not in path.read_text()
    assert len(path.read_text().splitlines()) == 5


def test_only_one_concurrent_verification_releases_request(tmp_path):
    service, notifier, _ = make_service(tmp_path)
    approval, code = create(service, notifier)
    results = []
    threads = [threading.Thread(target=lambda: results.append(service.verify_approval(code, request(), approval["approval_id"]))) for _ in range(8)]
    for thread in threads: thread.start()
    for thread in threads: thread.join()
    assert sum(result["approved"] for result in results) == 1


def test_create_approval_returns_masked_destination_and_no_code(tmp_path):
    service, notifier, _ = make_service(tmp_path)
    approval, _ = create(service, notifier)
    assert approval["destination"] == "r***@example.test"
    assert "code" not in approval and "code_hash" not in approval


def test_explicit_expire_prevents_later_use(tmp_path):
    service, notifier, _ = make_service(tmp_path)
    approval, code = create(service, notifier)
    assert service.expire_approval(approval["approval_id"])["status"] == "EXPIRED"
    assert service.verify_approval(code, request(), approval["approval_id"])["reason"] == "code_reused"
