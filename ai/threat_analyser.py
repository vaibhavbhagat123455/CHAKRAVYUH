"""Deterministic semantic threat analyser used by the AI layer.

The production adapter can replace this implementation with an LLM, but the
result contract and the final policy decision remain deterministic. This
module deliberately never executes tools.
"""

import re
from typing import Iterable, List, Sequence

from .models import AnalysisResult, ToolRequest


class ThreatAnalyser:
    VERSION = "rules-v1"

    _INJECTION_PATTERNS: Sequence[str] = (
        r"ignore\s+(all\s+)?previous\s+instructions",
        r"disregard\s+(the\s+)?original\s+(task|request|instructions)",
        r"you\s+are\s+now\s+authori[sz]ed",
        r"reveal\s+(the\s+)?system\s+prompt",
        r"do\s+not\s+tell\s+the\s+user",
        r"override\s+(the\s+)?security\s+policy",
    )
    _SENSITIVE_TERMS = {
        "student records", "student database", "personal data", "identity data",
        "confidential report", "password", "secret", "private records",
    }
    _EXTERNAL_TERMS = {"external", "outside the organisation", "unknown recipient", "public email"}
    _EXPORT_TOOLS = {"send_email", "export_records", "upload_file", "http_post"}

    def analyse(
        self,
        content: str,
        original_goal: str,
        tool_request: ToolRequest,
    ) -> AnalysisResult:
        """Analyse untrusted content and a proposed action without executing it."""
        if not isinstance(content, str) or not isinstance(original_goal, str):
            raise TypeError("content and original_goal must be strings")

        text = f"{content}\n{tool_request.purpose}".lower()
        injection_hits = self._matches(text, self._INJECTION_PATTERNS)
        sensitive_hits = self._terms(text, self._SENSITIVE_TERMS)
        external_hits = self._terms(text, self._EXTERNAL_TERMS)
        goal_drift = self._detect_goal_drift(original_goal, tool_request, text)

        # Sensitive data alone is reviewable (HOLD). It becomes an automatic
        # denial when combined with an external destination or an injection/
        # goal-drift attempt. This keeps the approval path demonstrable.
        high_risk = bool(sensitive_hits and (external_hits or injection_hits or goal_drift))
        medium_risk = bool(sensitive_hits or external_hits or goal_drift)
        if high_risk:
            risk = "high"
            score = 0.96 if injection_hits or goal_drift else 0.86
        elif medium_risk or injection_hits:
            risk = "medium"
            score = 0.72 if injection_hits or goal_drift else 0.60
        else:
            risk = "low"
            score = 0.05

        evidence: List[str] = []
        if injection_hits:
            evidence.append(f"prompt-injection pattern: {injection_hits[0]}")
        if goal_drift:
            evidence.append("proposed action is outside the authorised goal")
        if sensitive_hits:
            evidence.append(f"sensitive-data indicators: {', '.join(sensitive_hits)}")
        if external_hits:
            evidence.append(f"external-destination indicators: {', '.join(external_hits)}")

        if high_risk or injection_hits and goal_drift:
            action = "DENY"
        elif medium_risk:
            action = "HOLD"
        else:
            action = "ALLOW"

        reason = self._reason(action, injection_hits, goal_drift, sensitive_hits, external_hits)
        return AnalysisResult(
            prompt_injection=bool(injection_hits),
            goal_drift=goal_drift,
            sensitive_data_risk=risk,
            risk_score=score,
            recommended_action=action,
            reason=reason,
            evidence=evidence,
            analyser_version=self.VERSION,
        )

    @staticmethod
    def _matches(text: str, patterns: Iterable[str]) -> List[str]:
        return [pattern for pattern in patterns if re.search(pattern, text, re.IGNORECASE)]

    @staticmethod
    def _terms(text: str, terms: Iterable[str]) -> List[str]:
        return sorted(term for term in terms if term in text)

    @staticmethod
    def _detect_goal_drift(goal: str, request: ToolRequest, text: str) -> bool:
        goal_words = set(re.findall(r"[a-z]{4,}", goal.lower()))
        purpose_words = set(re.findall(r"[a-z]{4,}", request.purpose.lower()))
        goal_is_summary = any(word in goal.lower() for word in ("summarise", "summarize", "summary"))
        export_action = request.tool in ThreatAnalyser._EXPORT_TOOLS or any(
            word in text for word in ("export", "send", "upload", "email all")
        )
        unrelated_purpose = bool(goal_words and purpose_words and not goal_words.intersection(purpose_words))
        return (goal_is_summary and export_action) or unrelated_purpose

    @staticmethod
    def _reason(action: str, injections: List[str], drift: bool, sensitive: List[str], external: List[str]) -> str:
        if action == "DENY":
            return "The content attempts to change the authorised task or transfer sensitive data outside scope."
        if action == "HOLD":
            return "The action may be legitimate but requires human review because its scope or data sensitivity is high."
        return "The proposed action is aligned with the authorised task and contains no detected high-risk indicators."
