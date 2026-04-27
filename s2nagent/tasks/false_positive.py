"""
Task C — False Positive Filter

입력: finding 제목, 증거, 응답 본문
출력: {"verdict": "confirmed|likely_false_positive", "reason": "<brief>", "confidence": <0-100>}
"""

from __future__ import annotations

import json
from typing import Any

from s2nagent.constants import FP_VERDICTS
from s2nagent.tasks.base import BaseTask


class FalsePositiveTask(BaseTask):
    """스캔 결과가 실제 취약점인지 FP인지 판단합니다."""

    SYSTEM_PROMPT = (
        "You are S2N-Agent. Analyze a vulnerability finding and determine if it is a "
        "real vulnerability or a false positive. "
        "Return ONLY a JSON object: "
        "{\"verdict\": \"confirmed|likely_false_positive\", \"reason\": \"<brief>\", \"confidence\": <0-100>}."
    )

    def build_prompt(
        self,
        *,
        finding: str,
        evidence: str = "",
        response_body: str = "",
        **_: Any,
    ) -> str:
        data = {
            "finding": finding,
            "evidence": evidence[:300],
            "response_body": response_body[:500],
        }
        return f"Is this a real vulnerability or a false positive?\n{json.dumps(data, ensure_ascii=False)}"

    def parse_response(self, response: dict[str, Any]) -> dict[str, Any]:
        verdict = response.get("verdict", "likely_false_positive").lower()
        if verdict not in FP_VERDICTS:
            verdict = "likely_false_positive"
        return {
            "verdict": verdict,
            "reason": response.get("reason", ""),
            "confidence": int(response.get("confidence", 50)),
        }
