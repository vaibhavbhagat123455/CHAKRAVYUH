import json
from pathlib import Path

from ai.scenario_engine import ScenarioEngine
from ai.threat_analyser import ThreatAnalyser


ROOT = Path(__file__).parents[1]


def test_malicious_pdf_detects_injection_goal_drift_and_high_risk():
    result = ScenarioEngine().analyse(ScenarioEngine().load(ROOT / "scenarios/malicious_pdf.json"))
    assert result.prompt_injection is True
    assert result.goal_drift is True
    assert result.sensitive_data_risk == "high"
    assert result.recommended_action == "DENY"


def test_safe_summary_is_allowed():
    result = ScenarioEngine().analyse(ScenarioEngine().load(ROOT / "scenarios/safe_summary.json"))
    assert result.prompt_injection is False
    assert result.goal_drift is False
    assert result.sensitive_data_risk == "low"
    assert result.recommended_action == "ALLOW"


def test_approval_transfer_is_reviewable():
    result = ScenarioEngine().analyse(ScenarioEngine().load(ROOT / "scenarios/approval_transfer.json"))
    assert result.sensitive_data_risk == "high"
    assert result.recommended_action == "HOLD"


def test_analysis_is_json_serialisable_and_never_executes_tools():
    scenario = ScenarioEngine().load(ROOT / "scenarios/safe_summary.json")
    result = ScenarioEngine().analyse(scenario).to_dict()
    encoded = json.dumps(result, sort_keys=True)
    assert "summarize_document" not in encoded
    assert result["analyser_version"] == ThreatAnalyser.VERSION


def test_invalid_scenario_is_rejected(tmp_path):
    path = tmp_path / "invalid.json"
    path.write_text(json.dumps({"scenario_id": "x"}), encoding="utf-8")
    try:
        ScenarioEngine().load(path)
    except ValueError as exc:
        assert "missing fields" in str(exc)
    else:
        raise AssertionError("invalid scenario was accepted")
