"""
Task B — Payload Planning

입력: plugin, parameter, injection context
출력: {"payloads": ["...", ...], "strategy": "<brief>"}
"""

from __future__ import annotations

import json
from typing import Any

from s2nagent.tasks.base import BaseTask


class PayloadPlanningTask(BaseTask):
    """플러그인과 컨텍스트에 맞는 payload 목록을 생성합니다."""

    SYSTEM_PROMPT = (
        "You are S2N-Agent. Given a vulnerability plugin and injection context, "
        "generate a prioritized list of test payloads. "
        "Return ONLY a JSON object: "
        "{\"payloads\": [\"...\", ...], \"strategy\": \"<brief description>\"}. "
        "Maximum 10 payloads. Order by likelihood of success."
    )

    def build_prompt(
        self,
        *,
        plugin: str,
        parameter: str = "",
        context: str = "html_body",
        **_: Any,
    ) -> str:
        data = {
            "plugin": plugin,
            "parameter": parameter,
            "context": context,
        }
        return f"Generate test payloads:\n{json.dumps(data, ensure_ascii=False)}"

    def parse_response(self, response: dict[str, Any]) -> dict[str, Any]:
        payloads = response.get("payloads", [])
        if not isinstance(payloads, list):
            payloads = [str(payloads)]
        return {
            "payloads": payloads[:10],
            "strategy": response.get("strategy", ""),
        }
