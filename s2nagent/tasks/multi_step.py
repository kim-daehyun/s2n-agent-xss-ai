"""
Task D — Multi-step Planner

입력: 완료된 플러그인, 발견된 findings, sitemap 요약
출력: {"next_action": "<plugin_name|stop>", "reason": "<brief>", "priority": "high|medium|low"}
"""

from __future__ import annotations

import json
from typing import Any

from s2nagent.constants import PLUGINS_WITH_STOP
from s2nagent.tasks.base import BaseTask


class MultiStepPlannerTask(BaseTask):
    """스캔 진행 상황을 보고 다음 실행할 플러그인을 계획합니다."""

    SYSTEM_PROMPT = (
        "You are S2N-Agent. Given the completed plugins, current findings, and sitemap, "
        "decide the next best action to maximize vulnerability discovery. "
        "Return ONLY a JSON object: "
        "{\"next_action\": \"<plugin_name|stop>\", \"reason\": \"<brief>\", \"priority\": \"high|medium|low\"}. "
        f"Available actions: {', '.join(PLUGINS_WITH_STOP)}."
    )

    def build_prompt(
        self,
        *,
        completed: list[str],
        findings: list[dict[str, Any]],
        sitemap: str = "",
        **_: Any,
    ) -> str:
        data = {
            "completed_plugins": completed,
            "findings_summary": [
                {"plugin": f.get("plugin", ""), "severity": f.get("severity", "")}
                for f in findings[:20]  # 토큰 절약
            ],
            "sitemap_summary": sitemap[:300],
        }
        return f"Plan the next scan action:\n{json.dumps(data, ensure_ascii=False)}"

    def parse_response(self, response: dict[str, Any]) -> dict[str, Any]:
        action = response.get("next_action", "stop").lower()
        if action not in PLUGINS_WITH_STOP:
            action = "stop"
        priority = response.get("priority", "medium").lower()
        if priority not in {"high", "medium", "low"}:
            priority = "medium"
        return {
            "next_action": action,
            "reason": response.get("reason", ""),
            "priority": priority,
        }
