import json

from ui.dashboard import DashboardState


def test_complete_checkpoint_demo_records_and_verifies_all_paths(tmp_path):
    evidence_path = tmp_path / "security-log.jsonl"
    state = DashboardState(evidence_path=evidence_path, approval_log_path=tmp_path / "approval.jsonl")

    safe = state.run("safe_summary")
    malicious = state.run("malicious_pdf")
    held = state.run("approval_transfer")

    assert safe["decision"] == "ALLOW"
    assert malicious["decision"] == "DENY"
    assert held["decision"] == "HOLD"
    assert len(held["layers"]) == 7
    assert state.evidence.verify()["valid"] is True
    assert all("entry_hash" in event for event in state.evidence.read_entries())
    assert all("current_hash" not in event for event in state.evidence.read_entries())

    code = state.notifier.deliveries[-1]["code"]
    released = state.service.verify_approval(code, held["request"], held["approval_id"])
    assert released["approved"] is True
    reused = state.service.verify_approval(code, held["request"], held["approval_id"])
    assert reused["approved"] is False
    assert reused["reason"] == "code_reused"

    replay_one = state.evidence.replay()
    replay_two = state.evidence.replay()
    assert replay_one == replay_two
    assert {item["decision"] for item in replay_one["decisions"]} >= {"ALLOW", "HOLD", "DENY"}

    tampered = tmp_path / "tampered.jsonl"
    text = evidence_path.read_text(encoding="utf-8")
    tampered.write_text(text.replace('"decision":"DENY"', '"decision":"ALLOW"', 1), encoding="utf-8")
    from core.verify import verify_log
    result = verify_log(tampered)
    assert result.valid is False
    assert result.first_invalid is not None
