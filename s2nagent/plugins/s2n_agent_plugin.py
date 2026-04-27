"""
S2NAgentPlugin — S2N 플러그인 생명주기 훅 기반 LLM 오케스트레이터.

pre_scan  : sitemap 분석 → 실행할 플러그인 우선순위 결정 (ai_mode=smart|aggressive)
run       : 표준 플러그인 실행 위임 (ai_mode=assist 에서는 권고만 출력)
post_scan : 결과 해석 → 다음 스캔 계획 → session_data에 저장
cleanup   : 에이전트 상태 초기화

이 플러그인이 플러그인 목록에 추가되면 S2N Scanner가 pre/run/post_scan/cleanup을
자동으로 호출합니다 (scan_engine.py:466-512 참조).
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

logger = logging.getLogger("s2nagent.plugin")

_AI_MODES = {"off", "assist", "smart", "aggressive"}


class S2NAgentPlugin:
    """
    S2N 플러그인 인터페이스 구현체.

    Scanner.plugins 리스트에 추가하거나
    --ai-mode 옵션을 통해 runner.py에서 자동 주입됩니다.
    """

    name = "s2n_agent"

    def __init__(
        self,
        ai_mode: str = "smart",
        ai_model: str = "s2n-agent",
        ai_endpoint: str = "http://localhost:11434",
    ) -> None:
        if ai_mode not in _AI_MODES:
            raise ValueError(f"ai_mode must be one of {_AI_MODES}, got '{ai_mode}'")

        self.ai_mode = ai_mode
        self._client = self._build_client(ai_model, ai_endpoint)

        from s2nagent.tasks import (
            PluginSelectionTask,
            PayloadPlanningTask,
            FalsePositiveTask,
            MultiStepPlannerTask,
        )
        self._select_task = PluginSelectionTask(self._client)
        self._payload_task = PayloadPlanningTask(self._client)
        self._fp_task = FalsePositiveTask(self._client)
        self._plan_task = MultiStepPlannerTask(self._client)

        self._completed_plugins: list[str] = []
        self._all_findings: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Plugin lifecycle hooks
    # ------------------------------------------------------------------

    def pre_scan(self, plugin_context: Any) -> None:
        """
        스캔 전 — SiteMap을 읽어 어떤 플러그인을 실행할지 결정.
        session_data["agent_state"]["plan"]에 플러그인 우선순위 목록을 저장합니다.
        """
        if self.ai_mode == "off":
            return

        sitemap = getattr(plugin_context.scan_context, "sitemap", None)
        pages = getattr(sitemap, "pages", []) if sitemap else []

        sitemap_summary = self._summarize_sitemap(pages)
        target_url = plugin_context.scan_context.config.target_url

        logger.info("[S2N-Agent] pre_scan: sitemap=%d pages, target=%s", len(pages), target_url)

        # 첫 번째 페이지 DOM 스니펫 (있는 경우)
        first_dom = ""
        if pages:
            first_page = pages[0]
            first_dom = getattr(first_page, "dom_snippet", "") or getattr(first_page, "body", "")[:300]

        try:
            decision = self._select_task.run(
                url=target_url,
                dom=first_dom,
                sitemap_summary=sitemap_summary,
            )
            logger.info(
                "[S2N-Agent] Plugin recommendation: %s (confidence=%d%%) — %s",
                decision["plugin"],
                decision["confidence"],
                decision.get("reason", ""),
            )

            # 세션 데이터에 에이전트 계획 저장
            agent_state = plugin_context.scan_context.session_data.get("agent_state", {})
            agent_state["plan"] = [decision["plugin"]]
            agent_state["plugin_recommendation"] = decision
            agent_state["next_actions"] = []
            plugin_context.scan_context.session_data["agent_state"] = agent_state

        except Exception as exc:
            logger.warning("[S2N-Agent] pre_scan 실패 (기존 스캔 계속): %s", exc)

    def run(self, plugin_context: Any) -> None:
        """
        실제 스캔 실행.
        assist 모드: AI 권고를 로그에만 출력.
        smart/aggressive 모드: 권고된 플러그인을 동적으로 실행.

        NOTE: run()이 None을 반환하면 scan_engine은 post_scan()을 호출합니다.
        """
        if self.ai_mode == "assist":
            agent_state = plugin_context.scan_context.session_data.get("agent_state", {})
            rec = agent_state.get("plugin_recommendation", {})
            if rec:
                logger.info(
                    "[S2N-Agent] ASSIST 권고: '%s' 플러그인 실행을 고려하세요 (confidence=%d%%)",
                    rec.get("plugin", "N/A"),
                    rec.get("confidence", 0),
                )
        # smart/aggressive: post_scan에서 다음 스텝 계획
        return None

    def post_scan(self, plugin_context: Any) -> Any:
        """
        스캔 후 — 결과 해석 + 다음 액션 계획.
        session_data["agent_state"]["next_actions"]를 업데이트합니다.
        """
        if self.ai_mode == "off":
            return self._empty_result(plugin_context)

        # 현재까지 완료된 플러그인 + findings 수집
        all_results = getattr(plugin_context.scan_context, "plugin_results", [])
        for r in all_results:
            pname = getattr(r, "plugin_name", "")
            if pname and pname not in self._completed_plugins:
                self._completed_plugins.append(pname)
            for f in getattr(r, "findings", []):
                self._all_findings.append({
                    "plugin": pname,
                    "severity": getattr(f, "severity", ""),
                    "title": getattr(f, "title", ""),
                })

        sitemap = getattr(plugin_context.scan_context, "sitemap", None)
        pages = getattr(sitemap, "pages", []) if sitemap else []
        sitemap_summary = self._summarize_sitemap(pages)

        # FP 필터 (findings가 있는 경우)
        filtered_findings = self._filter_false_positives()

        try:
            next_plan = self._plan_task.run(
                completed=self._completed_plugins,
                findings=filtered_findings,
                sitemap=sitemap_summary,
            )
            logger.info(
                "[S2N-Agent] 다음 액션: %s (priority=%s) — %s",
                next_plan["next_action"],
                next_plan["priority"],
                next_plan.get("reason", ""),
            )

            agent_state = plugin_context.scan_context.session_data.get("agent_state", {})
            agent_state["completed_plugins"] = self._completed_plugins[:]
            agent_state["next_actions"] = [next_plan]
            plugin_context.scan_context.session_data["agent_state"] = agent_state

        except Exception as exc:
            logger.warning("[S2N-Agent] post_scan 실패: %s", exc)

        return self._empty_result(plugin_context)

    def cleanup(self, plugin_context: Any) -> None:
        """에이전트 내부 상태 초기화."""
        self._completed_plugins.clear()
        self._all_findings.clear()
        logger.debug("[S2N-Agent] 정리 완료.")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_client(self, model: str, endpoint: str) -> Any:
        """Ollama 우선, 실패 시 HuggingFace 클라이언트 반환."""
        from s2nagent.client.ollama import OllamaClient, OllamaError  # noqa: F401
        client = OllamaClient(endpoint=endpoint, model=model)
        if client.is_available():
            logger.info("[S2N-Agent] Ollama 서버 연결 확인: %s / %s", endpoint, model)
            return client

        logger.warning(
            "[S2N-Agent] Ollama 미접속 (%s/%s) — HuggingFace 로컬 추론으로 전환.", endpoint, model
        )
        from s2nagent.client.huggingface import HuggingFaceClient
        return HuggingFaceClient(repo_id=model)

    @staticmethod
    def _summarize_sitemap(pages: list[Any]) -> str:
        """SiteMap 페이지 목록을 간략한 문자열로 요약합니다."""
        if not pages:
            return "no pages crawled"
        urls = [getattr(p, "url", str(p)) for p in pages[:20]]
        form_count = sum(1 for p in pages if getattr(p, "has_forms", False))
        file_input_count = sum(1 for p in pages if getattr(p, "has_file_input", False))
        login_count = sum(1 for p in pages if getattr(p, "has_login_form", False))
        return (
            f"{len(pages)} pages, {form_count} with forms, "
            f"{file_input_count} with file inputs, {login_count} login forms. "
            f"Sample URLs: {', '.join(urls[:5])}"
        )

    def _filter_false_positives(self) -> list[dict[str, Any]]:
        """FP 필터를 통과한 findings만 반환합니다."""
        if not self._all_findings:
            return []
        confirmed = []
        for f in self._all_findings:
            try:
                result = self._fp_task.run(
                    finding=f.get("title", ""),
                    evidence=f.get("evidence", ""),
                    response_body=f.get("response_body", ""),
                )
                if result.get("verdict") == "confirmed":
                    confirmed.append(f)
            except Exception:
                confirmed.append(f)  # 에러 시 보수적으로 유지
        return confirmed

    @staticmethod
    def _empty_result(plugin_context: Any) -> Any:
        """빈 PluginResult 반환 (스캔 엔진 인터페이스 충족)."""
        try:
            from s2n.s2nscanner.interfaces import PluginResult, PluginStatus
            return PluginResult(
                plugin_name="s2n_agent",
                status=PluginStatus.SUCCESS,
                start_time=datetime.utcnow(),
                end_time=datetime.utcnow(),
                metadata={"agent": True},
            )
        except ImportError:
            return None
