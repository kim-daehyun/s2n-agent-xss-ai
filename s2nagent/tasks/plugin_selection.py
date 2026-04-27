"""
Task A — Plugin Selection

입력: URL, DOM 스니펫, sitemap 요약
출력: {"plugin": "<name>", "confidence": <0-100>}
"""

from __future__ import annotations

import json
from typing import Any

from s2nagent.constants import PLUGINS
from s2nagent.tasks.base import BaseTask


class PluginSelectionTask(BaseTask):
    """주어진 URL/DOM/SiteMap 컨텍스트에서 가장 적합한 플러그인을 선택합니다."""

    SYSTEM_PROMPT = (
        "You are S2N-Agent, a web vulnerability scanner AI. "
        "Analyze the given web context and select the single most relevant security plugin. "
        "Return ONLY a JSON object: {\"plugin\": \"<name>\", \"confidence\": <0-100>, \"reason\": \"<brief>\"}. "
        f"Available plugins: {', '.join(PLUGINS)}."
    )

    def build_prompt(
        self,
        *,
        url: str,
        dom: str = "",
        sitemap_summary: str = "",
        **_: Any,
    ) -> str:
        data = {
            "url": url,
            "dom": dom[:500],  # 토큰 절약
            "sitemap_summary": sitemap_summary,
        }
        return f"Select the best security plugin for this web context:\n{json.dumps(data, ensure_ascii=False)}"

    def parse_response(self, response: dict[str, Any]) -> dict[str, Any]:
        plugin = response.get("plugin", "").lower()
        if plugin not in PLUGINS:
            plugin = "xss"  # 안전한 기본값
        return {
            "plugin": plugin,
            "confidence": int(response.get("confidence", 50)),
            "reason": response.get("reason", ""),
        }
