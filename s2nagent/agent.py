"""
S2NAgent — 최상위 오케스트레이터.

S2N Scanner 외부에서 독립적으로 사용하거나,
on_finding 콜백으로 실시간 피드백에 활용됩니다.
"""

from __future__ import annotations

import logging
from typing import Any

from s2nagent.client.ollama import OllamaClient, OllamaError
from s2nagent.tasks import (
    FalsePositiveTask,
    MultiStepPlannerTask,
    PayloadPlanningTask,
    PluginSelectionTask,
)

logger = logging.getLogger("s2nagent.agent")


class S2NAgent:
    """
    S2N-Agent 메인 클래스.

    사용 예시 (on_finding 콜백):

        agent = S2NAgent(endpoint="http://localhost:11434", model="s2n-agent")
        scanner = Scanner(config=config, on_finding=agent.analyze_finding)
    """

    def __init__(
        self,
        endpoint: str = "http://localhost:11434",
        model: str = "s2n-agent",
        mode: str = "smart",
    ) -> None:
        self.mode = mode
        client = OllamaClient(endpoint=endpoint, model=model)
        if not client.is_available():
            logger.warning(
                "Ollama 미접속 (%s/%s) — HuggingFace로 전환", endpoint, model
            )
            from s2nagent.client.huggingface import HuggingFaceClient
            client = HuggingFaceClient(repo_id=model)

        self._select = PluginSelectionTask(client)
        self._payload = PayloadPlanningTask(client)
        self._fp = FalsePositiveTask(client)
        self._plan = MultiStepPlannerTask(client)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def select_plugin(self, url: str, dom: str = "", sitemap_summary: str = "") -> dict[str, Any]:
        """Task A: 주어진 컨텍스트에서 최적 플러그인 선택."""
        return self._select.run(url=url, dom=dom, sitemap_summary=sitemap_summary)

    def plan_payloads(self, plugin: str, parameter: str = "", context: str = "html_body") -> dict[str, Any]:
        """Task B: 플러그인과 파라미터에 맞는 payload 목록 생성."""
        return self._payload.run(plugin=plugin, parameter=parameter, context=context)

    def filter_false_positive(self, finding: str, evidence: str = "", response_body: str = "") -> dict[str, Any]:
        """Task C: Finding이 실제 취약점인지 FP인지 판단."""
        return self._fp.run(finding=finding, evidence=evidence, response_body=response_body)

    def plan_next_action(
        self,
        completed: list[str],
        findings: list[dict[str, Any]],
        sitemap: str = "",
    ) -> dict[str, Any]:
        """Task D: 다음 스캔 액션 계획."""
        return self._plan.run(completed=completed, findings=findings, sitemap=sitemap)

    def analyze_finding(self, finding: Any) -> None:
        """
        on_finding 콜백 — Finding 인스턴스를 실시간으로 분석합니다.
        결과는 로그에 출력됩니다.
        """
        title = getattr(finding, "title", str(finding))
        evidence = getattr(finding, "evidence", "")
        response = getattr(finding, "response", None)
        body = getattr(response, "body", "") if response else ""

        try:
            result = self.filter_false_positive(finding=title, evidence=evidence, response_body=body)
            verdict = result.get("verdict", "unknown")
            confidence = result.get("confidence", 0)
            reason = result.get("reason", "")
            logger.info(
                "[S2N-Agent] Finding '%s' → %s (%d%%) — %s",
                title,
                verdict,
                confidence,
                reason,
            )
        except Exception as exc:
            logger.debug("[S2N-Agent] analyze_finding 실패: %s", exc)
