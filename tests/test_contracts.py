import json
import tempfile
import unittest
from pathlib import Path

from core.contracts import canonical_json
from core.policies import evaluate_policy
from core.schemas import Decision, DecisionSignals, LogEvent, ToolRequest
from tests.log_helpers import build_demo_log, read_lines, scenario_records

ROOT = Path(__file__).parents[1]
try:
    from ai.models import AnalysisResult as AIAnalysisResult
    from ai.models import ToolRequest as AIToolRequest
except ImportError:  # AI code is merged on the integration branch.
    AIAnalysisResult = None
    AIToolRequest = None


def load_schema(name: str) -> dict:
    return json.loads((ROOT / "schemas" / name).read_text(encoding="utf-8"))


class ContractTests(unittest.TestCase):
    def test_tool_request_round_trip_and_fingerprint(self):
        record = scenario_records()[0]
        request = record["request"]
        restored = ToolRequest.from_dict(request.to_dict())
        self.assertEqual(restored, request)
        changed = ToolRequest(
            request.request_id,
            request.tool,
            {"recipient": "other@example.test", "file": "synthetic_student_records.pdf"},
            request.purpose,
            request.scenario_id,
        )
        self.assertNotEqual(request.fingerprint(), changed.fingerprint())

    def test_decision_round_trip(self):
        record = scenario_records()[0]
        decision = evaluate_policy(record["request"], record["signals"])
        restored = Decision.from_dict(decision.to_dict())
        self.assertEqual(restored.to_dict(), decision.to_dict())

    def test_log_event_round_trip(self):
        with tempfile.TemporaryDirectory() as tempdir:
            path = Path(tempdir) / "security_log.jsonl"
            build_demo_log(path)
            raw = json.loads(read_lines(path)[0])
        event = LogEvent.from_dict(raw)
        self.assertEqual(event.to_dict(), raw)

    def test_signals_accept_existing_ai_result_shape_when_available(self):
        if AIAnalysisResult is None:
            self.skipTest("ai/ is not present on this branch")
        request = AIToolRequest(
            "req",
            "summarize_document",
            {"file": "synthetic_public_circular.pdf"},
            "summary",
            "scenario",
        )
        result = AIAnalysisResult(
            prompt_injection=False,
            goal_drift=False,
            sensitive_data_risk="low",
            risk_score=0.05,
            recommended_action="ALLOW",
            reason="safe",
            evidence=[],
            analyser_version="rules-v1",
        )
        signals = DecisionSignals.from_mapping(result.to_dict())
        self.assertEqual(signals.recommended_action, "ALLOW")
        self.assertEqual(signals.analyser_version, "rules-v1")
        self.assertEqual(request.tool, "summarize_document")

    def test_schemas_validate_contract_objects(self):
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema is not installed")

        record = scenario_records()[0]
        request = record["request"]
        decision = evaluate_policy(request, record["signals"])
        jsonschema.validate(request.to_dict(), load_schema("tool_request.schema.json"))
        jsonschema.validate(decision.to_dict(), load_schema("decision.schema.json"))

        with tempfile.TemporaryDirectory() as tempdir:
            path = Path(tempdir) / "security_log.jsonl"
            build_demo_log(path)
            schema = load_schema("log_event.schema.json")
            for line in read_lines(path):
                jsonschema.validate(json.loads(line), schema)

    def test_canonical_json_is_the_shared_representation(self):
        self.assertEqual(canonical_json({"b": 2, "a": 1}), '{"a":1,"b":2}')


if __name__ == "__main__":
    unittest.main(verbosity=2)
