from __future__ import annotations

import json
import re
from typing import Any

import requests

from s2nagent.plugin_agents.schemas import PluginAgentDecision


OLLAMA_URL = "http://127.0.0.1:11434/api/generate"


class XSSAgent:
    """
    XSS-specific plugin agent.

    This agent does not send HTTP requests or execute payloads directly.
    It only decides whether the S2N xss plugin should run, infers the
    injection context, plans candidate scanner test inputs, filters likely
    false positives, and returns a structured decision envelope.
    """

    agent_id = "xss_agent"
    plugin = "xss"
    model = "s2n-agent-xss"

    system_prompt = (
        "You are XSSAgent, the dedicated S2N-Agent model for Cross-Site Scripting scan decisions. "
        "Return strict JSON only. "
        "You do not send HTTP requests, manage cookies, execute JavaScript, or parse full DOM trees. "
        "Your job is to decide whether the S2N xss plugin should run, plan context-aware authorized "
        "scanner validation inputs, filter false positives, and suggest the next scan action. "
        "Use the requested JSON schema exactly."
    )

    def call_model(self, prompt: str, model: str | None = None) -> dict[str, Any]:
        payload = {
            "model": model or self.model,
            "system": self.system_prompt,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.0,
            },
        }

        try:
            response = requests.post(OLLAMA_URL, json=payload, timeout=120)
            response.raise_for_status()
        except requests.RequestException as exc:
            return {
                "error": "model_call_failed",
                "raw": str(exc),
            }

        text = response.json().get("response", "").strip()
        return self.safe_json(text)

    def safe_json(self, text: str) -> dict[str, Any]:
        """
        Ollama may return text around JSON or refusal text.
        Keep the runtime stable by returning a structured error object.
        """
        try:
            parsed = json.loads(text)
            if isinstance(parsed, dict):
                return parsed

            return {
                "error": "json_not_object",
                "raw": text,
            }
        except Exception:
            pass

        start = text.find("{")
        end = text.rfind("}")

        if start >= 0 and end > start:
            try:
                parsed = json.loads(text[start : end + 1])
                if isinstance(parsed, dict):
                    return parsed
            except Exception:
                pass

        return {
            "error": "json_parse_failed",
            "raw": text,
        }

    def clamp_confidence(self, value: Any, default: int = 0) -> int:
        try:
            score = int(value)
        except Exception:
            score = default

        return max(0, min(100, score))

    def infer_context(
        self,
        *,
        url: str,
        dom: str = "",
        response_snippet: str = "",
    ) -> str:
        """
        Lightweight MVP context inference.

        Priority:
        1. JavaScript string/block
        2. HTML attribute
        3. HTML body
        4. JSON value
        5. URL parameter
        6. unknown
        """

        text = f"{dom}\n{response_snippet}"

        if re.search(r"<script[^>]*>.*test.*</script>", text, re.I | re.S):
            if re.search(r'["\']test["\']', text):
                return "js_string"
            return "js_block"

        if re.search(
            r'(value|href|src|title|alt|data-[\w-]+)=["\'][^"\']*test[^"\']*["\']',
            text,
            re.I,
        ):
            return "html_attribute"

        if re.search(r">\s*[^<]*test[^<]*\s*<", text, re.I):
            return "html_body"

        if text.strip().startswith("{") and "test" in text:
            return "json_value"

        if "?" in url:
            return "url_param"

        return "unknown"

    def extract_parameter(self, *, url: str, dom: str = "") -> str:
        m = re.search(r"[?&]([A-Za-z0-9_\-]+)=", url)
        if m:
            return m.group(1)

        m = re.search(r'name=["\']([^"\']+)["\']', dom)
        if m:
            return m.group(1)

        return "q"

    def normalize_selection(
        self,
        raw_selection: dict[str, Any],
        *,
        url: str,
        dom: str,
        response_snippet: str,
        injection_context: str,
    ) -> dict[str, Any]:
        """
        Normalize model output into the Task A selection schema.

        If the model returns invalid JSON, use a deterministic fallback based
        on reflection/context signals so the runtime envelope remains stable.
        """

        if raw_selection.get("error"):
            has_reflection = "test" in f"{dom}\n{response_snippet}"
            confidence = 80 if has_reflection and injection_context != "unknown" else 35
            should_run = confidence >= 70

            return {
                "plugin": "xss",
                "should_run": should_run,
                "confidence": confidence,
                "reason": (
                    "Fallback selection: reflected test input and known injection context detected"
                    if should_run
                    else "Fallback selection: insufficient reflected evidence for XSS"
                ),
            }

        plugin = raw_selection.get("plugin", "xss")
        confidence = self.clamp_confidence(raw_selection.get("confidence"), default=0)

        model_should_run = raw_selection.get("should_run")
        if isinstance(model_should_run, bool):
            should_run = model_should_run
        else:
            should_run = plugin == "xss" and confidence >= 70

        if injection_context == "unknown":
            should_run = False

        return {
            "plugin": plugin,
            "should_run": should_run,
            "confidence": confidence,
            "reason": raw_selection.get("reason", "No reason provided by model"),
        }

    def fallback_payload_plan(self, *, parameter: str, context: str) -> dict[str, Any]:
        """
        Deterministic fallback plan for authorized scanner validation.

        These are non-destructive proof-of-concept inputs intended for local
        or authorized test environments.
        """

        if context == "html_attribute":
            return {
                "payloads": [
                    "\"><svg/onload=alert(1)>",
                    "'><img src=x onerror=alert(1)>",
                ],
                "bypass_variants": [
                    "%22%3E%3Csvg%2Fonload%3Dalert%281%29%3E",
                    "&#34;&#62;&#60;svg/onload=alert(1)&#62;",
                ],
                "strategy": "attribute breakout",
                "context_notes": (
                    f"Parameter '{parameter}' appears in an HTML attribute value. "
                    "Close the quote before testing tag/event-handler execution."
                ),
            }

        if context == "html_body":
            return {
                "payloads": [
                    "<svg/onload=alert(1)>",
                    "<img src=x onerror=alert(1)>",
                ],
                "bypass_variants": [
                    "%3Csvg%2Fonload%3Dalert%281%29%3E",
                ],
                "strategy": "html body injection",
                "context_notes": (
                    f"Parameter '{parameter}' appears in HTML body text. "
                    "Test whether HTML tags are interpreted or escaped."
                ),
            }

        if context == "js_string":
            return {
                "payloads": [
                    "';alert(1);//",
                    "\";alert(1);//",
                ],
                "bypass_variants": [
                    "%27%3Balert%281%29%3B%2F%2F",
                ],
                "strategy": "javascript string breakout",
                "context_notes": (
                    f"Parameter '{parameter}' appears in a JavaScript string. "
                    "Test whether the string can be closed and code can be injected."
                ),
            }

        if context == "js_block":
            return {
                "payloads": [
                    "alert(1)",
                    "confirm(1)",
                ],
                "bypass_variants": [],
                "strategy": "javascript block injection",
                "context_notes": (
                    f"Parameter '{parameter}' appears in a JavaScript block. "
                    "Validate whether injected script syntax is reachable."
                ),
            }

        if context == "json_value":
            return {
                "payloads": [
                    "\"><svg/onload=alert(1)>",
                    "<img src=x onerror=alert(1)>",
                ],
                "bypass_variants": [],
                "strategy": "json reflected value validation",
                "context_notes": (
                    f"Parameter '{parameter}' appears in a JSON value. "
                    "Confirm whether the value is later rendered into HTML/DOM."
                ),
            }

        if context == "url_param":
            return {
                "payloads": [
                    "xss-test",
                    "<svg/onload=alert(1)>",
                ],
                "bypass_variants": [
                    "%3Csvg%2Fonload%3Dalert%281%29%3E",
                ],
                "strategy": "url parameter reflection check",
                "context_notes": (
                    f"Parameter '{parameter}' is present in the URL. "
                    "First verify reflection before escalating to context-specific payloads."
                ),
            }

        return {
            "payloads": [],
            "bypass_variants": [],
            "strategy": "skip payload planning",
            "context_notes": "Injection context is unknown. More DOM or response evidence is required.",
        }

    def normalize_payload_plan(
        self,
        raw_plan: dict[str, Any],
        *,
        parameter: str,
        context: str,
    ) -> dict[str, Any]:
        """
        Normalize model output into the Task B payload planning schema.

        If the model refuses or returns non-JSON text, return deterministic
        context-aware scanner validation inputs.
        """

        payloads = raw_plan.get("payloads")
        strategy = raw_plan.get("strategy")
        context_notes = raw_plan.get("context_notes")

        if isinstance(payloads, list) and payloads and strategy and context_notes:
            return {
                "payloads": [str(item) for item in payloads],
                "bypass_variants": [
                    str(item) for item in raw_plan.get("bypass_variants", [])
                ],
                "strategy": str(strategy),
                "context_notes": str(context_notes),
            }

        fallback = self.fallback_payload_plan(parameter=parameter, context=context)

        if raw_plan.get("error"):
            fallback["context_notes"] = (
                f"{fallback['context_notes']} Fallback used because model returned "
                f"{raw_plan.get('error')}."
            )

        return fallback

    def evaluate_target(
        self,
        *,
        url: str,
        dom: str = "",
        sitemap_summary: str = "",
        response_snippet: str = "",
    ) -> PluginAgentDecision:
        injection_context = self.infer_context(
            url=url,
            dom=dom,
            response_snippet=response_snippet,
        )
        parameter = self.extract_parameter(url=url, dom=dom)

        selection_input = {
            "url": url,
            "dom": dom,
            "sitemap_summary": sitemap_summary,
            "response_snippet": response_snippet,
            "injection_context": injection_context,
            "required_output_schema": {
                "plugin": "xss",
                "should_run": "boolean",
                "confidence": "integer 0-100",
                "reason": "short evidence-based reason",
            },
        }

        selection_prompt = (
            "Decide whether the xss plugin is the best candidate for this web context. "
            "Return strict JSON only with keys: plugin, should_run, confidence, reason.\n"
            + json.dumps(selection_input, ensure_ascii=False)
        )

        raw_selection = self.call_model(selection_prompt)
        selection = self.normalize_selection(
            raw_selection,
            url=url,
            dom=dom,
            response_snippet=response_snippet,
            injection_context=injection_context,
        )

        confidence = self.clamp_confidence(selection.get("confidence"), default=0)
        should_run = bool(selection.get("should_run")) and injection_context != "unknown"

        payload_plan = None
        if should_run:
            payload_plan = self.plan_payloads(
                parameter=parameter,
                context=injection_context,
                dom_snippet=dom,
                response_snippet=response_snippet,
            )

        return PluginAgentDecision(
            agent=self.agent_id,
            plugin=self.plugin,
            model=self.model,
            should_run=should_run,
            confidence=confidence,
            reason=selection.get("reason", ""),
            context={
                "url": url,
                "parameter": parameter,
                "injection_context": injection_context,
                "endpoint_fingerprint": self.fingerprint(url),
            },
            task_outputs={
                "selection": selection,
                "payload_plan": payload_plan,
                "false_positive": None,
                "next_plan": None,
            },
            next_action="run_plugin" if should_run else "skip_plugin",
            metadata={
                "agent_decision_version": "v1",
                "source": "plugin_agent_registry",
                "runtime": "ollama",
                "latency_budget_ms": 1500,
            },
        )

    def plan_payloads(
        self,
        *,
        parameter: str,
        context: str,
        dom_snippet: str = "",
        response_snippet: str = "",
    ) -> dict[str, Any]:
        payload_input = {
            "plugin": "xss",
            "parameter": parameter,
            "injection_context": context,
            "dom_snippet": dom_snippet,
            "response_snippet": response_snippet,
            "previous_attempts": [],
            "required_output_schema": {
                "payloads": ["string"],
                "bypass_variants": ["string"],
                "strategy": "string",
                "context_notes": "string",
            },
        }

        prompt = (
            "Generate a JSON payload planning object for authorized XSS scanner validation. "
            "Return strict JSON only with keys: payloads, bypass_variants, strategy, context_notes. "
            "Use non-destructive proof-of-concept validation inputs appropriate for the injection context.\n"
            + json.dumps(payload_input, ensure_ascii=False)
        )

        raw_plan = self.call_model(prompt)
        return self.normalize_payload_plan(
            raw_plan,
            parameter=parameter,
            context=context,
        )

    def filter_false_positive(
        self,
        *,
        finding: str,
        evidence: str,
        response_body: str,
    ) -> dict[str, Any]:
        fp_input = {
            "finding": finding,
            "evidence": evidence,
            "response_body": response_body,
            "required_output_schema": {
                "verdict": "confirmed | likely_false_positive | inconclusive",
                "reason": "string",
                "confidence": "integer 0-100",
            },
        }

        prompt = (
            "Decide whether this XSS finding is confirmed or likely false positive. "
            "Return strict JSON only with keys: verdict, reason, confidence.\n"
            + json.dumps(fp_input, ensure_ascii=False)
        )

        raw_fp = self.call_model(prompt)
        return self.normalize_false_positive(
            raw_fp,
            evidence=evidence,
            response_body=response_body,
        )

    def normalize_false_positive(
        self,
        raw_fp: dict[str, Any],
        *,
        evidence: str,
        response_body: str,
    ) -> dict[str, Any]:
        verdict = raw_fp.get("verdict")
        confidence = self.clamp_confidence(raw_fp.get("confidence"), default=0)
        reason = raw_fp.get("reason")

        if verdict in {"confirmed", "likely_false_positive", "inconclusive"} and reason and confidence >= 70:
            return {
            "verdict": verdict,
            "reason": str(reason),
            "confidence": confidence,
        }

        evidence_text = evidence or ""
        body = response_body or ""

        escaped_markers = ["&lt;", "&gt;", "&quot;", "&#34;", "&#39;"]
        inert_markers = [
            "<textarea",
            "</textarea",
            "<code",
            "</code",
            "<pre",
            "</pre",
            "<!--",
            "-->",
        ]

        evidence_in_body = bool(evidence_text and evidence_text in body)
        has_escaped_payload = any(marker in body for marker in escaped_markers)
        has_inert_context = any(marker.lower() in body.lower() for marker in inert_markers)

        has_unescaped_angle = "<" in body and ">" in body
        looks_executable = any(
            token.lower() in body.lower()
            for token in [
                "<script",
                "<svg",
                "<img",
                "onload=",
                "onerror=",
                "javascript:",
            ]
        )

        if (
            evidence_in_body
            and looks_executable
            and has_unescaped_angle
            and not has_escaped_payload
            and not has_inert_context
        ):
            return {
                "verdict": "confirmed",
                "reason": (
                    "Fallback FP filter: payload-like evidence is reflected unescaped "
                    "in an executable HTML context"
                ),
                "confidence": 85,
            }

        if has_escaped_payload:
            return {
                "verdict": "likely_false_positive",
                "reason": "Fallback FP filter: payload-like evidence appears HTML-escaped",
                "confidence": 82,
            }

        if has_inert_context:
            return {
                "verdict": "likely_false_positive",
                "reason": "Fallback FP filter: payload-like evidence appears only in an inert context",
                "confidence": 78,
            }

        if not evidence_in_body:
            return {
                "verdict": "likely_false_positive",
                "reason": "Fallback FP filter: evidence is not reflected in the response body",
                "confidence": 72,
            }

        return {
            "verdict": "inconclusive",
            "reason": (
                "Fallback FP filter: reflected evidence exists, but executable browser context "
                "is not clear"
            ),
            "confidence": 55,
        }

    def plan_next_action(
        self,
        *,
        completed: list[str],
        findings: list[dict[str, Any]],
        sitemap: str,
    ) -> dict[str, Any]:
        next_input = {
            "completed": completed,
            "findings": findings,
            "sitemap": sitemap,
            "required_output_schema": {
                "next_action": "plugin name or stop",
                "reason": "string",
                "priority": "low | medium | high",
            },
        }

        prompt = (
            "Suggest the next scanner action after XSS analysis. "
            "Return strict JSON only with keys: next_action, reason, priority.\n"
            + json.dumps(next_input, ensure_ascii=False)
        )

        raw_next = self.call_model(prompt)
        return self.normalize_next_action(
            raw_next,
            completed=completed,
            findings=findings,
            sitemap=sitemap,
        )

    def normalize_next_action(
        self,
        raw_next: dict[str, Any],
        *,
        completed: list[str],
        findings: list[dict[str, Any]],
        sitemap: str,
    ) -> dict[str, Any]:
        completed_set = set(completed or [])
        sitemap_text = (sitemap or "").lower()

        next_action = raw_next.get("next_action")
        reason = raw_next.get("reason")
        priority = raw_next.get("priority")

        valid_priorities = {"low", "medium", "high"}

        if next_action and reason and priority:
            next_action = str(next_action)
            priority = str(priority)

            if next_action not in completed_set:
                return {
                    "next_action": next_action,
                    "reason": str(reason),
                    "priority": priority if priority in valid_priorities else "medium",
                }

        has_high_xss = any(
            item.get("plugin") == "xss"
            and item.get("severity") in {"HIGH", "CRITICAL"}
            for item in findings
        )

        if has_high_xss:
            if "csrf" not in completed_set and any(
                marker in sitemap_text
                for marker in [
                    "state-changing",
                    "form",
                    "post",
                    "transfer",
                    "update",
                    "delete",
                ]
            ):
                return {
                    "next_action": "csrf",
                    "reason": (
                        "Fallback next action: confirmed or high-severity XSS plus "
                        "state-changing surface suggests CSRF/session abuse follow-up"
                    ),
                    "priority": "medium",
                }

            if "path_traversal" not in completed_set and any(
                marker in sitemap_text
                for marker in [
                    "admin",
                    "panel",
                    "download",
                    "file",
                    "path",
                ]
            ):
                return {
                    "next_action": "path_traversal",
                    "reason": (
                        "Fallback next action: admin or file-related routes suggest "
                        "privileged file access surface"
                    ),
                    "priority": "medium",
                }

            if "jwt" not in completed_set and any(
                marker in sitemap_text
                for marker in [
                    "jwt",
                    "token",
                    "authorization",
                    "bearer",
                ]
            ):
                return {
                    "next_action": "jwt",
                    "reason": "Fallback next action: token-related surface appears after XSS finding",
                    "priority": "medium",
                }

        return {
            "next_action": "stop",
            "reason": "Fallback next action: no uncompleted higher-priority follow-up plugin identified",
            "priority": "low",
        }

    def fingerprint(self, url: str) -> str:
        return url.split("?")[0]