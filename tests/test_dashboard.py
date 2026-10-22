import json

from ui.evidence import EvidenceLog, GENESIS
from ui.dashboard import DashboardState


def test_hash_chain_verifies_and_replay_is_stable(tmp_path):
    log = EvidenceLog(tmp_path / "events.jsonl")
    log.append({"event_id": "evt-1", "event_type": "SCENARIO_DECISION", "request_id": "req-1", "decision": "ALLOW", "evidence_id": "ev-1"})
    log.append({"event_id": "evt-2", "event_type": "SCENARIO_DECISION", "request_id": "req-2", "decision": "HOLD", "evidence_id": "ev-2"})
    assert log.verify()["valid"]
    assert log.read_entries()[0]["previous_hash"] == GENESIS
    assert log.replay() == log.replay()


def test_hash_chain_reports_modified_entry(tmp_path):
    path = tmp_path / "events.jsonl"
    log = EvidenceLog(path)
    log.append({"event_id": "evt-1", "event_type": "SCENARIO_DECISION", "decision": "ALLOW"})
    entry = json.loads(path.read_text())
    entry["decision"] = "DENY"
    path.write_text(json.dumps(entry) + "\n")
    result = log.verify()
    assert not result["valid"] and result["line_number"] == 1


def test_dashboard_fixtures_render_all_decision_states_and_seven_layers(tmp_path):
    state = DashboardState(evidence_path=tmp_path / "events.jsonl", approval_log_path=tmp_path / "approvals.jsonl")
    outcomes = {name: state.run(name) for name in ("safe_summary", "approval_transfer", "malicious_pdf")}
    assert {item["decision"] for item in outcomes.values()} == {"ALLOW", "HOLD", "DENY"}
    assert all(len(item["layers"]) == 7 for item in outcomes.values())
    assert "code" not in outcomes["approval_transfer"]
    assert state.evidence.verify()["valid"]


def test_dashboard_approval_releases_only_matching_fixture_request(tmp_path):
    state = DashboardState(evidence_path=tmp_path / "events.jsonl", approval_log_path=tmp_path / "approvals.jsonl")
    held = state.run("approval_transfer")
    code = state.notifier.deliveries[-1]["code"]
    result = state.service.verify_approval(code, held["request"], held["approval_id"])
    assert result["approved"] and result["resumed"] == "released"
    assert state.scenarios[held["request"]["request_id"]]["decision"] == "ALLOW"
    assert state.evidence.verify()["valid"]
