from pathlib import Path

from approval.approval_codes import ApprovalService
from approval.notification import MockNotificationAdapter
from core.pdf_scanner import inspect_pdf
from core.replay import replay_log
from core.verify import verify_log
from proxy.stdio_client import StdioMcpClient


ROOT = Path(__file__).parents[1]


def test_real_pdf_fixture_is_parsed_and_hashable():
    safe = inspect_pdf(ROOT / "data/fixtures/synthetic_public_circular.pdf")
    malicious = inspect_pdf(ROOT / "data/fixtures/synthetic_malicious_student_records.pdf")
    assert safe.page_count == 1 and safe.safe
    assert malicious.page_count == 1 and not malicious.safe
    assert {"prompt_injection", "sensitive_data", "external_transfer"}.issubset(malicious.indicators)
    assert len(malicious.sha256) == 64


def test_approval_digest_binds_purpose_and_scenario(tmp_path):
    notifier = MockNotificationAdapter()
    service = ApprovalService(notifier, log_path=tmp_path / "approval.jsonl", code_factory=lambda: "123456")
    request = {"request_id": "req-1", "tool": "send_email", "arguments": {},
               "purpose": "send report", "scenario_id": "scenario-a"}
    approval = service.create_approval(request, "reviewer@example.test")
    altered = {**request, "purpose": "send secrets"}
    assert service.verify_approval("123456", altered, approval["approval_id"])["reason"] == "request_mismatch"


def test_standalone_approval_events_are_hash_chained(tmp_path):
    path = tmp_path / "approval.jsonl"
    notifier = MockNotificationAdapter()
    service = ApprovalService(notifier, log_path=path, code_factory=lambda: "123456")
    request = {"request_id": "req-1", "tool": "send_email", "arguments": {}}
    approval = service.create_approval(request, "reviewer@example.test")
    service.verify_approval("123456", request, approval["approval_id"])
    assert verify_log(path).valid
    assert all("entry_hash" in line for line in path.read_text(encoding="utf-8").splitlines())


def test_dashboard_boundary_is_a_real_stdio_json_rpc_process(tmp_path):
    path = tmp_path / "security_log.jsonl"
    client = StdioMcpClient(log_path=path, approval_secret="test-secret")
    try:
        response = client.call_tool({"request_id": "req-safe", "tool": "summarize_document",
                                     "arguments": {"file": "notice.pdf"},
                                     "purpose": "Summarise public notice", "scenario_id": "safe"},
                                    "Public notice.")
        assert response["result"]["decision"] == "ALLOW"
        assert response["jsonrpc"] == "2.0"
    finally:
        client.close()
    assert verify_log(path).valid


def test_replay_reports_final_approval_outcome(tmp_path):
    from ui.dashboard import DashboardState

    path = tmp_path / "security_log.jsonl"
    state = DashboardState(evidence_path=path, approval_log_path=tmp_path / "approval.jsonl")
    try:
        held = state.run("approval_transfer")
        code = state.notifier.deliveries[-1]["code"]
        state.service.verify_approval(code, held["request"], held["approval_id"])
        replay = replay_log(path)
        assert replay.valid
        assert any(item.final_decision == "ALLOW" for item in replay.decisions)
    finally:
        state.close()
