"""
S2NAgent — 최상위 오케스트레이터.

S2N Scanner 외부에서 독립적으로 사용하거나,
on_finding 콜백으로 실시간 피드백에 활용됩니다.

Week 3 변경:
- analyze_finding: FP 판정 + confirmed 시 payload 추가 권고 + 멀티스텝 트리거
- finding_stream: 수집된 finding 목록 (멀티스텝 플래너 입력용)
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("s2nagent.agent")


class S2NAgent:
    """
    S2N-Agent 메인 클래스.

    on_finding 콜백 사용 예시:
        agent = S2NAgent(endpoint="http://localhost:11434", model="s2n-agent")
        scanner = Scanner(config=config, on_finding=agent.analyze_finding)

    독립 실행 예시:
        agent = S2NAgent()
        result = agent.select_plugin(url="/search?q=test", dom="<input name=q>")
    """

    def __init__(
        self,
        endpoint: str = "http://localhost:11434",
        model: str = "s2n-agent",
        mode: str = "smart",
    ) -> None:
        self.mode = mode
        self._client = self._build_client(endpoint, model)

        from s2nagent.tasks import (
            FalsePositiveTask,
            MultiStepPlannerTask,
            PayloadPlanningTask,
            PluginSelectionTask,
        )
        self._select = PluginSelectionTask(self._client)
        self._payload = PayloadPlanningTask(self._client)
        self._fp = FalsePositiveTask(self._client)
        self._plan = MultiStepPlannerTask(self._client)

        # on_finding 콜백으로 수집된 finding 스트림
        self.finding_stream: list[dict[str, Any]] = []
        self._completed_plugins: list[str] = []

    # ------------------------------------------------------------------
    # Tasks API
    # ------------------------------------------------------------------

    def select_plugin(self, url: str, dom: str = "", sitemap_summary: str = "") -> dict[str, Any]:
        """Task A: 최적 플러그인 선택."""
        return self._select.run(url=url, dom=dom, sitemap_summary=sitemap_summary)

    def plan_payloads(
        self,
        plugin: str,
        parameter: str = "",
        context: str = "html_body",
        dom_snippet: str = "",
        response_snippet: str = "",
    ) -> dict[str, Any]:
        """Task B: payload 목록 + bypass 변형 생성."""
        return self._payload.run(
            plugin=plugin,
            parameter=parameter,
            context=context,
            dom_snippet=dom_snippet,
            response_snippet=response_snippet,
        )

    def filter_false_positive(
        self, finding: str, evidence: str = "", response_body: str = ""
    ) -> dict[str, Any]:
        """Task C: FP 판별."""
        return self._fp.run(finding=finding, evidence=evidence, response_body=response_body)

    def plan_next_action(
        self,
        completed: list[str],
        findings: list[dict[str, Any]],
        sitemap: str = "",
    ) -> dict[str, Any]:
        """Task D: 다음 스캔 액션 계획."""
        return self._plan.run(completed=completed, findings=findings, sitemap=sitemap)

    # ------------------------------------------------------------------
    # on_finding 콜백
    # ------------------------------------------------------------------

    def analyze_finding(self, finding: Any) -> None:
        """
        on_finding 콜백 — Finding 인스턴스를 실시간으로 분석합니다.

        처리 흐름:
        1. FP 필터 판정
        2. confirmed → payload 추가 권고 로그 (aggressive 모드)
        3. finding_stream 누적
        4. aggressive 모드에서 3개 이상 confirmed 발견 시 멀티스텝 플래너 호출
        """
        title = getattr(finding, "title", str(finding))
        evidence = getattr(finding, "evidence", "") or ""
        plugin_name = getattr(finding, "plugin", "")
        severity = str(getattr(finding, "severity", ""))
        response = getattr(finding, "response", None)
        body = (getattr(response, "body", "") or "")[:500] if response else ""

        entry: dict[str, Any] = {
            "plugin": plugin_name,
            "severity": severity,
            "title": title,
        }

        # ── FP 판정 ──────────────────────────────────────────────────
        try:
            fp_result = self.filter_false_positive(
                finding=title, evidence=evidence, response_body=body
            )
            verdict = fp_result.get("verdict", "unknown")
            confidence = fp_result.get("confidence", 0)
            reason = fp_result.get("reason", "")

            logger.info(
                "[S2N-Agent] Finding '%s' → %s (%d%%) — %s",
                title, verdict, confidence, reason,
            )
            entry.update({"fp_verdict": verdict, "fp_confidence": confidence})

            # ── confirmed: payload 추가 권고 ─────────────────────────
            if verdict == "confirmed" and self.mode == "aggressive" and plugin_name:
                try:
                    plan = self.plan_payloads(
                        plugin=plugin_name,
                        response_snippet=evidence[:200],
                    )
                    if plan.get("payloads"):
                        logger.info(
                            "[S2N-Agent] AGGRESSIVE 후속 payload (%d개): %s",
                            len(plan["payloads"]),
                            plan["payloads"][0],
                        )
                except Exception as exc:
                    logger.debug("[S2N-Agent] 후속 payload 실패: %s", exc)

        except Exception as exc:
            logger.debug("[S2N-Agent] FP 판정 실패: %s", exc)

        self.finding_stream.append(entry)

        # ── aggressive: 3개 이상 confirmed 시 멀티스텝 플래너 ────────
        if self.mode == "aggressive":
            confirmed = [
                f for f in self.finding_stream
                if f.get("fp_verdict") == "confirmed"
            ]
            if len(confirmed) >= 3 and len(confirmed) % 3 == 0:
                self._trigger_multiplan()

    def _trigger_multiplan(self) -> None:
        """finding_stream 기반으로 다음 스캔 액션을 계획합니다."""
        confirmed = [
            f for f in self.finding_stream if f.get("fp_verdict") == "confirmed"
        ]
        try:
            plan = self.plan_next_action(
                completed=self._completed_plugins,
                findings=confirmed[-10:],
            )
            logger.info(
                "[S2N-Agent] 멀티스텝 플래너 → 다음 액션: %s (priority=%s) — %s",
                plan.get("next_action"),
                plan.get("priority"),
                plan.get("reason", ""),
            )
        except Exception as exc:
            logger.debug("[S2N-Agent] 멀티스텝 플래너 실패: %s", exc)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _build_client(endpoint: str, model: str) -> Any:
        from s2nagent.client.ollama import OllamaClient
        client = OllamaClient(endpoint=endpoint, model=model)
        if client.is_available():
            logger.info("[S2N-Agent] Ollama 연결: %s / %s", endpoint, model)
            return client
        logger.warning("[S2N-Agent] Ollama 미접속 — HuggingFace로 전환.")
        from s2nagent.client.huggingface import HuggingFaceClient
        return HuggingFaceClient(repo_id=model)
