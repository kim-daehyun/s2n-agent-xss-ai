"""
S2NAgentPlugin — S2N 플러그인 생명주기 훅 기반 LLM 오케스트레이터.

pre_scan  : sitemap 분석 → 플러그인 선택 → payload 계획 (Week 3 추가)
run       : assist 모드에서 권고 출력
post_scan : FP 필터 → 다음 액션 계획 → session_data 저장
cleanup   : 에이전트 상태 초기화

scan_engine.py:466-512 의 pre/run/post_scan/cleanup 훅을 통해 자동 호출됩니다.
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
            FalsePositiveTask,
            MultiStepPlannerTask,
            PayloadPlanningTask,
            PluginSelectionTask,
        )
        self._select_task = PluginSelectionTask(self._client)
        self._payload_task = PayloadPlanningTask(self._client)
        self._fp_task = FalsePositiveTask(self._client)
        self._plan_task = MultiStepPlannerTask(self._client)

        self._completed_plugins: list[str] = []
        self._all_findings: list[dict[str, Any]] = []
        # on_finding으로 수집된 실시간 findings
        self._realtime_findings: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Plugin lifecycle hooks
    # ------------------------------------------------------------------

    def pre_scan(self, plugin_context: Any) -> None:
        """
        스캔 전:
        1. sitemap 분석 → 최적 플러그인 선택
        2. 선택된 플러그인에 맞는 payload 계획 (Week 3)
        결과를 session_data["agent_state"]에 저장합니다.
        """
        if self.ai_mode == "off":
            return

        sitemap = getattr(plugin_context.scan_context, "sitemap", None)
        pages = getattr(sitemap, "pages", []) if sitemap else []
        sitemap_summary = self._summarize_sitemap(pages)
        target_url = plugin_context.scan_context.config.target_url

        logger.info("[S2N-Agent] pre_scan: sitemap=%d pages, target=%s", len(pages), target_url)

        first_dom = ""
        if pages:
            first_page = pages[0]
            first_dom = (
                getattr(first_page, "dom_snippet", "")
                or getattr(first_page, "body", "")[:400]
            )

        agent_state = plugin_context.scan_context.session_data.get("agent_state", {})

        # ── Step 1: Plugin Selection ──────────────────────────────────
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
            agent_state["plan"] = [decision["plugin"]]
            agent_state["plugin_recommendation"] = decision
            agent_state["next_actions"] = []
        except Exception as exc:
            logger.warning("[S2N-Agent] plugin selection 실패: %s", exc)
            decision = {}

        # ── Step 2: Payload Planning (Week 3) ────────────────────────
        if decision and self.ai_mode in ("smart", "aggressive"):
            try:
                selected_plugin = decision.get("plugin", "")
                # DOM에서 첫 번째 파라미터명 추출 (간단한 휴리스틱)
                param = _extract_param(first_dom)
                # injection context 추론
                context = _infer_context(first_dom, selected_plugin)

                payload_plan = self._payload_task.run(
                    plugin=selected_plugin,
                    parameter=param,
                    context=context,
                    dom_snippet=first_dom[:300],
                )
                logger.info(
                    "[S2N-Agent] Payload plan: %d payloads, %d bypass variants — %s",
                    len(payload_plan.get("payloads", [])),
                    len(payload_plan.get("bypass_variants", [])),
                    payload_plan.get("strategy", ""),
                )
                agent_state["payload_plan"] = payload_plan
            except Exception as exc:
                logger.warning("[S2N-Agent] payload planning 실패: %s", exc)

        plugin_context.scan_context.session_data["agent_state"] = agent_state

    def run(self, plugin_context: Any) -> None:
        """
        assist 모드: AI 권고(플러그인 + payload)를 로그에 출력.
        smart/aggressive 모드: post_scan에서 결과 반영.
        NOTE: None 반환 시 scan_engine이 post_scan()을 호출합니다.
        """
        if self.ai_mode == "assist":
            agent_state = plugin_context.scan_context.session_data.get("agent_state", {})
            rec = agent_state.get("plugin_recommendation", {})
            plan = agent_state.get("payload_plan", {})
            if rec:
                logger.info(
                    "[S2N-Agent] ASSIST — 플러그인 권고: '%s' (confidence=%d%%)",
                    rec.get("plugin", "N/A"),
                    rec.get("confidence", 0),
                )
            if plan and plan.get("payloads"):
                logger.info(
                    "[S2N-Agent] ASSIST — 페이로드 권고 (%d개): %s ...",
                    len(plan["payloads"]),
                    plan["payloads"][0] if plan["payloads"] else "",
                )
        return None

    def post_scan(self, plugin_context: Any) -> Any:
        """
        스캔 후:
        1. 완료된 플러그인 + findings 수집 (plugin_results + realtime_findings 통합)
        2. FP 필터 적용
        3. 다음 액션 계획 → session_data 저장
        """
        if self.ai_mode == "off":
            return self._empty_result(plugin_context)

        # plugin_results 에서 수집
        all_results = getattr(plugin_context.scan_context, "plugin_results", [])
        for r in all_results:
            pname = getattr(r, "plugin_name", "")
            if pname and pname not in self._completed_plugins:
                self._completed_plugins.append(pname)
            for f in getattr(r, "findings", []):
                entry = {
                    "plugin": pname,
                    "severity": str(getattr(f, "severity", "")),
                    "title": getattr(f, "title", ""),
                    "evidence": getattr(f, "evidence", ""),
                    "response_body": _get_response_body(f),
                }
                if entry not in self._all_findings:
                    self._all_findings.append(entry)

        # realtime_findings (on_finding 콜백 경로) 병합
        for rf in self._realtime_findings:
            if rf not in self._all_findings:
                self._all_findings.append(rf)

        sitemap = getattr(plugin_context.scan_context, "sitemap", None)
        pages = getattr(sitemap, "pages", []) if sitemap else []
        sitemap_summary = self._summarize_sitemap(pages)

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
            agent_state["confirmed_findings"] = filtered_findings
            agent_state["next_actions"] = [next_plan]
            plugin_context.scan_context.session_data["agent_state"] = agent_state
        except Exception as exc:
            logger.warning("[S2N-Agent] post_scan 실패: %s", exc)

        return self._empty_result(plugin_context)

    def cleanup(self, plugin_context: Any) -> None:
        """에이전트 내부 상태 초기화."""
        self._completed_plugins.clear()
        self._all_findings.clear()
        self._realtime_findings.clear()
        logger.debug("[S2N-Agent] 정리 완료.")

    def on_finding(self, finding: Any) -> None:
        """
        on_finding 콜백 진입점 (Week 3).
        Scanner의 on_finding 파라미터에 직접 연결됩니다.

        실시간으로:
        1. FP 필터 판정 → 로그 출력
        2. confirmed finding → payload planner 추가 권고
        3. self._realtime_findings 에 누적 (post_scan에서 합산)
        """
        title = getattr(finding, "title", str(finding))
        evidence = getattr(finding, "evidence", "")
        plugin_name = getattr(finding, "plugin", "")
        severity = str(getattr(finding, "severity", ""))
        response_body = _get_response_body(finding)

        entry = {
            "plugin": plugin_name,
            "severity": severity,
            "title": title,
            "evidence": evidence,
            "response_body": response_body,
        }

        # FP 필터
        try:
            fp_result = self._fp_task.run(
                finding=title,
                evidence=evidence,
                response_body=response_body,
            )
            verdict = fp_result.get("verdict", "unknown")
            confidence = fp_result.get("confidence", 0)
            reason = fp_result.get("reason", "")

            logger.info(
                "[S2N-Agent] on_finding '%s' → %s (%d%%) — %s",
                title, verdict, confidence, reason,
            )

            entry["fp_verdict"] = verdict
            entry["fp_confidence"] = confidence

            # confirmed finding → 추가 payload 권고 (aggressive 모드)
            if verdict == "confirmed" and self.ai_mode == "aggressive":
                self._suggest_followup_payloads(plugin_name, evidence)

        except Exception as exc:
            logger.debug("[S2N-Agent] on_finding FP 판정 실패: %s", exc)

        self._realtime_findings.append(entry)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _suggest_followup_payloads(self, plugin: str, evidence: str) -> None:
        """confirmed finding 발생 시 후속 payload 권고 (aggressive 전용)."""
        try:
            plan = self._payload_task.run(
                plugin=plugin,
                context="html_body",
                response_snippet=evidence[:200],
            )
            if plan.get("payloads"):
                logger.info(
                    "[S2N-Agent] AGGRESSIVE — '%s' 후속 payload 권고 (%d개): %s",
                    plugin,
                    len(plan["payloads"]),
                    plan["payloads"][0],
                )
        except Exception as exc:
            logger.debug("[S2N-Agent] followup payload 실패: %s", exc)

    def _build_client(self, model: str, endpoint: str) -> Any:
        from s2nagent.client.ollama import OllamaClient
        client = OllamaClient(endpoint=endpoint, model=model)
        if client.is_available():
            logger.info("[S2N-Agent] Ollama 연결 확인: %s / %s", endpoint, model)
            return client
        logger.warning("[S2N-Agent] Ollama 미접속 — HuggingFace로 전환.")
        from s2nagent.client.huggingface import HuggingFaceClient
        return HuggingFaceClient(repo_id=model)

    @staticmethod
    def _summarize_sitemap(pages: list[Any]) -> str:
        if not pages:
            return "no pages crawled"
        urls: list[str] = []
        form_count = file_input_count = login_count = 0
        for p in pages:
            if len(urls) < 20:
                urls.append(getattr(p, "url", str(p)))
            form_count += bool(getattr(p, "has_forms", False))
            file_input_count += bool(getattr(p, "has_file_input", False))
            login_count += bool(getattr(p, "has_login_form", False))
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
            # on_finding에서 이미 판정된 경우 재사용
            if "fp_verdict" in f:
                if f["fp_verdict"] == "confirmed":
                    confirmed.append(f)
                continue
            try:
                result = self._fp_task.run(
                    finding=f.get("title", ""),
                    evidence=f.get("evidence", ""),
                    response_body=f.get("response_body", ""),
                )
                if result.get("verdict") == "confirmed":
                    confirmed.append(f)
            except Exception:
                confirmed.append(f)
        return confirmed

    @staticmethod
    def _empty_result(plugin_context: Any) -> Any:
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


# ------------------------------------------------------------------
# DOM 분석 헬퍼 (플러그인 내부 유틸)
# ------------------------------------------------------------------

def _extract_param(dom: str) -> str:
    """DOM 스니펫에서 첫 번째 input name 속성값을 추출합니다."""
    import re
    m = re.search(r'<input[^>]+name=["\']?([^"\'>\s]+)', dom, re.IGNORECASE)
    return m.group(1) if m else "q"


def _infer_context(dom: str, plugin: str) -> str:
    """DOM과 플러그인 유형으로 injection context를 추론합니다."""
    dom_lower = dom.lower()
    if plugin == "sqlinjection":
        return "sql_string" if "'" in dom else "sql_numeric"
    if plugin in ("xss", "autobot"):
        if "value=" in dom_lower:
            return "html_attribute"
        if "<script" in dom_lower:
            return "js_string"
        return "html_body"
    if plugin == "oscommand":
        return "shell_arg"
    if plugin == "path_traversal":
        return "path_segment"
    if plugin in ("brute_force", "soft_brute_force"):
        return "http_header"
    return "url_param"


def _get_response_body(finding: Any) -> str:
    """Finding에서 응답 본문을 안전하게 추출합니다."""
    response = getattr(finding, "response", None)
    if response is None:
        return ""
    body = getattr(response, "body", "") or ""
    return body[:500]
