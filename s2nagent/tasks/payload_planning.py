"""
Task B — Payload Planning (Week 3 강화)

입력: plugin, parameter, injection context, DOM 스니펫, 응답 스니펫
출력:
  {
    "payloads": ["...", ...],          # 우선순위 순 페이로드 목록 (최대 10개)
    "bypass_variants": ["...", ...],   # 인코딩/필터 우회 변형 (최대 5개)
    "strategy": "...",                 # 공략 전략 설명
    "context_notes": "..."             # 컨텍스트별 주의사항
  }
"""

from __future__ import annotations

import json
from typing import Any

from s2nagent.tasks.base import BaseTask

# 컨텍스트별 주입 힌트 — 프롬프트 품질 향상용
_CONTEXT_HINTS: dict[str, str] = {
    "html_body":      "payload injected directly into HTML body",
    "html_attribute": "payload injected into an HTML attribute value (quote escape needed)",
    "js_string":      "payload injected inside a JavaScript string literal",
    "js_block":       "payload injected inside a JavaScript code block",
    "url_param":      "payload injected as a URL query parameter (URL encoding may apply)",
    "json_value":     "payload injected as a JSON string value",
    "xml_node":       "payload injected into an XML/SVG node",
    "http_header":    "payload injected into an HTTP header value",
    "sql_string":     "payload injected into a SQL string context",
    "sql_numeric":    "payload injected into a SQL numeric context (no quotes needed)",
    "shell_arg":      "payload injected as a shell command argument",
    "path_segment":   "payload injected as a URL path segment",
}


class PayloadPlanningTask(BaseTask):
    """
    플러그인·파라미터·컨텍스트·DOM·응답을 종합해 최적 payload 목록을 생성합니다.

    Week 3 추가:
    - DOM 스니펫 분석 (input type, attribute context 추론)
    - 응답 스니펫 분석 (필터/WAF 패턴 감지)
    - bypass_variants: 인코딩·우회 변형 자동 생성
    - context_notes: 컨텍스트별 주의사항
    """

    SYSTEM_PROMPT = (
        "You are S2N-Agent, a web security expert. "
        "Analyze the injection context and generate optimized test payloads. "
        "Return ONLY a JSON object with these exact keys:\n"
        "  payloads: list of up to 10 payloads ordered by success likelihood\n"
        "  bypass_variants: list of up to 5 encoding/filter bypass variants\n"
        "  strategy: brief string describing the attack strategy\n"
        "  context_notes: brief string about context-specific considerations\n"
        "Example: {\"payloads\": [\"<svg/onload=alert(1)>\"], "
        "\"bypass_variants\": [\"%3Csvg%2Fonload%3Dalert(1)%3E\"], "
        "\"strategy\": \"DOM XSS via reflected input\", "
        "\"context_notes\": \"attribute context — close quote first\"}"
    )

    def build_prompt(
        self,
        *,
        plugin: str,
        parameter: str = "",
        context: str = "html_body",
        dom_snippet: str = "",
        response_snippet: str = "",
        previous_attempts: list[str] | None = None,
        **_: Any,
    ) -> str:
        context_hint = _CONTEXT_HINTS.get(context, context)

        data: dict[str, Any] = {
            "plugin": plugin,
            "parameter": parameter,
            "injection_context": context,
            "context_hint": context_hint,
        }
        if dom_snippet:
            data["dom_snippet"] = dom_snippet[:300]
        if response_snippet:
            # WAF/필터 탐지에 활용
            data["response_snippet"] = response_snippet[:300]
        if previous_attempts:
            # 이미 시도한 페이로드는 제외하도록 모델에 알림
            data["already_tried"] = previous_attempts[:5]

        return f"Generate optimized security test payloads:\n{json.dumps(data, ensure_ascii=False)}"

    def parse_response(self, response: dict[str, Any]) -> dict[str, Any]:
        payloads = response.get("payloads", [])
        if not isinstance(payloads, list):
            payloads = [str(payloads)]

        bypass = response.get("bypass_variants", [])
        if not isinstance(bypass, list):
            bypass = []

        return {
            "payloads": [str(p) for p in payloads[:10]],
            "bypass_variants": [str(p) for p in bypass[:5]],
            "strategy": str(response.get("strategy", "")),
            "context_notes": str(response.get("context_notes", "")),
        }
