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
    injection context, plans candidate payloads, and returns a structured
    decision envelope.
    """

    agent_id = "xss_agent"
    plugin = "xss"
    model = "s2n-agent-xss"

    system_prompt = (
        "You are XSSAgent, the dedicated S2N-Agent model for Cross-Site Scripting scan decisions. "
        "Return strict JSON only. "
        "You do not send HTTP requests, manage cookies, execute JavaScript, or parse full DOM trees. "
        "Your job is to decide whether the S2N xss plugin should run, plan context-aware payloads, "
        "filter false positives, and suggest the next scan action. "
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

        response = requests.post(OLLAMA_URL, json=payload, timeout=120)
        response.raise_for_status()

        text = response.json().get("response", "").strip()
        return self.safe_json(text)

    def safe_json(self, text: str) -> dict[str, Any]:
        try:
            return json.loads(text)
        except Exception:
            pass

        start = text.find("{")
        end = text.rfind("}")

        if start >= 0 and end > start:
            try:
                return json.loads(text[start : end + 1])
            except Exception:
                pass

        return {
            "error": "json_parse_failed",
            "raw": text,
        }

    def infer_context(self, *, url: str, dom: str = "", response_snippet: str = "") -> str:
        """
        Lightweight MVP context inference.

        Later, this can be replaced or complemented by model-based context
        classification and fine-tuned outputs.
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

    def evaluate_target(
        self,
        *,
        url: str,
        dom: str = "",
        sitemap_summary: str = "",
        response_snippet: str = "",
    ) -> PluginAgentDecision:
        selection_input = {
            "url": url,
            "dom": dom,
            "sitemap_summary": sitemap_summary,
            "response_snippet": response_snippet,
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

        selection = self.call_model(selection_prompt)

        injection_context = self.infer_context(
            url=url,
            dom=dom,
            response_snippet=response_snippet,
        )
        parameter = self.extract_parameter(url=url, dom=dom)

        confidence = int(selection.get("confidence", 0) or 0)
        model_should_run = selection.get("should_run")

        if isinstance(model_should_run, bool):
            should_run = model_should_run and injection_context != "unknown"
        else:
            should_run = (
                selection.get("plugin") == "xss"
                and confidence >= 70
                and injection_context != "unknown"
            )

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
            "Generate XSS payloads for the provided injection context. "
            "Return strict JSON only with keys: payloads, bypass_variants, strategy, context_notes. "
            "Use payloads appropriate for the context and avoid destructive behavior.\n"
            + json.dumps(payload_input, ensure_ascii=False)
        )

        return self.call_model(prompt)

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

        return self.call_model(prompt)

    def fingerprint(self, url: str) -> str:
        return url.split("?")[0]