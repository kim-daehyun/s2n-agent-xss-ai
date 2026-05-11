from __future__ import annotations

import json
import random
from pathlib import Path
from typing import Any


SEED = 20260508
rng = random.Random(SEED)

OUT_DIR = Path("data/plugin_agents/xss_clean")
OUT_RAW = OUT_DIR / "raw.jsonl"
OUT_TRAIN = OUT_DIR / "train.jsonl"
OUT_VALID = OUT_DIR / "valid.jsonl"
OUT_TEST = OUT_DIR / "test.jsonl"
OUT_REPORT = OUT_DIR / "dataset_report.json"

SYSTEM_PROMPT = """You are XSSAgent, the dedicated S2N-Agent model for Cross-Site Scripting scan decisions.

Return strict JSON only.
Do not include markdown.
Do not include explanations outside JSON.

You do not send HTTP requests, manage cookies, execute JavaScript, or parse full DOM trees.

Your job is to:
- decide whether the S2N xss plugin should run
- plan context-aware authorized scanner validation inputs
- filter false positives
- suggest the next scan action

Use the requested JSON schema exactly.
"""


SPLIT_CONFIG = {
    "train": {
        "count_per_task": 450,
        "prefix": "tr",
        "word": "training",
    },
    "valid": {
        "count_per_task": 75,
        "prefix": "va",
        "word": "validation",
    },
    "test": {
        "count_per_task": 75,
        "prefix": "te",
        "word": "holdout",
    },
}


PARAMS = ["q", "keyword", "search", "comment", "body", "name", "bio", "term"]


def write_jsonl(path: Path, records: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


def write_json(path: Path, obj: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, ensure_ascii=False, indent=2), encoding="utf-8")


def render_tpl(template: str, param: str, n: int, split: str) -> str:
    """
    Replace only our explicit placeholders.
    Handles both {param}/{n} and {{param}}/{{n}} forms.
    Then normalizes remaining double braces that came from template escaping.
    """
    rendered = (
        template
        .replace("{{param}}", param)
        .replace("{{n}}", str(n))
        .replace("{{split}}", split)
        .replace("{param}", param)
        .replace("{n}", str(n))
        .replace("{split}", split)
    )

    # No final dataset sample should contain template-escape double braces.
    # Single JSON/JS braces are valid; double braces are only template artifacts.
    rendered = rendered.replace("{{", "{").replace("}}", "}")

    return rendered


def normalize_template_artifacts(obj: Any) -> Any:
    """
    Remove leftover template artifacts from nested payloads.
    This is a safety net after render_tpl().
    """
    if isinstance(obj, dict):
        return {k: normalize_template_artifacts(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [normalize_template_artifacts(v) for v in obj]
    if isinstance(obj, str):
        return (
            obj
            .replace("{{param}}", "{param}")
            .replace("{{n}}", "{n}")
            .replace("{{split}}", "{split}")
            .replace("{{", "{")
            .replace("}}", "}")
        )
    return obj


def make_record(
    record_id: str,
    task: str,
    instruction: str,
    payload: dict[str, Any],
    assistant_json: dict[str, Any],
) -> dict[str, Any]:
    """
    expected_json and assistant output intentionally use the same schema.
    Evaluator may compare only part of it, but the training target should remain explicit.
    """
    payload = normalize_template_artifacts(payload)
    assistant_json = normalize_template_artifacts(assistant_json)

    return {
        "id": record_id,
        "task": task,
        "plugin": "xss",
        "agent": "xss_agent",
        "expected_json": assistant_json,
        "messages": [
            {
                "role": "system",
                "content": SYSTEM_PROMPT,
            },
            {
                "role": "user",
                "content": instruction + "\n" + json.dumps(payload, ensure_ascii=False),
            },
            {
                "role": "assistant",
                "content": json.dumps(assistant_json, ensure_ascii=False),
            },
        ],
    }


def build_selection_records(split: str, count: int) -> list[dict[str, Any]]:
    instruction = (
        "Decide whether the xss plugin should run for this web context. "
        "Return strict JSON only with keys: plugin, should_run, confidence, injection_context, "
        "parameter, reason_type, reason."
    )

    cfg = SPLIT_CONFIG[split]
    prefix = cfg["prefix"]
    word = cfg["word"]

    cases = [
        {
            "name": "html_body",
            "positive": True,
            "url_tpl": f"/{prefix}/search?{{param}}=test-{{n}}",
            "dom_tpl": f"<section class='{word}-result'>test-{{n}}</section>",
            "snippet_tpl": f"<section class='{word}-result'>test-{{n}}</section>",
            "summary": f"{word} sample: reflected input appears in HTML body text",
            "injection_context": "html_body",
            "confidence": 82,
            "reason_type": "reflected_html_body",
        },
        {
            "name": "html_attribute",
            "positive": True,
            "url_tpl": f"/{prefix}/filter?{{param}}=test-{{n}}",
            "dom_tpl": f"<input data-split='{word}' name='{{param}}' value='test-{{n}}'>",
            "snippet_tpl": f"<input data-split='{word}' name='{{param}}' value='test-{{n}}'>",
            "summary": f"{word} sample: reflected input appears in HTML attribute value",
            "injection_context": "html_attribute",
            "confidence": 82,
            "reason_type": "reflected_html_attribute",
        },
        {
            "name": "js_string",
            "positive": True,
            "url_tpl": f"/{prefix}/posts?{{param}}=test-{{n}}",
            "dom_tpl": f"<script>const {prefix}_value_{{n}} = 'test-{{n}}';</script>",
            "snippet_tpl": f"<script>const {prefix}_value_{{n}} = 'test-{{n}}';</script>",
            "summary": f"{word} sample: reflected input appears inside JavaScript string context",
            "injection_context": "js_string",
            "confidence": 86,
            "reason_type": "reflected_js_string",
        },
        {
            "name": "json_value",
            "positive": True,
            "url_tpl": f"/{prefix}/api/profile?{{param}}=test-{{n}}",
            "dom_tpl": "",
            "snippet_tpl": f'{{"split":"{word}","data":{{"{{param}}":"test-{{n}}"}}}}',
            "summary": f"{word} sample: reflected JSON value may be rendered by client code",
            "injection_context": "json_value",
            "confidence": 68,
            "reason_type": "reflected_json_value",
        },
        {
            "name": "url_param_reflection",
            "positive": True,
            "url_tpl": f"/{prefix}/results?{{param}}=test-{{n}}",
            "dom_tpl": f"<a href='/{prefix}/results?{{param}}=test-{{n}}'>result</a>",
            "snippet_tpl": f"<a href='/{prefix}/results?{{param}}=test-{{n}}'>result</a>",
            "summary": f"{word} sample: user-controlled URL parameter is reflected in response",
            "injection_context": "url_param",
            "confidence": 68,
            "reason_type": "reflected_url_parameter",
        },
        {
            "name": "static_asset",
            "positive": False,
            "url_tpl": f"/{prefix}/static/app-{{n}}.js",
            "dom_tpl": "",
            "snippet_tpl": f"function {prefix}_app_{{n}}() {{ return true; }}",
            "summary": f"{word} sample: static asset with no user-controlled reflected input",
            "reason_type": "static_asset",
        },
        {
            "name": "download_surface",
            "positive": False,
            "url_tpl": f"/{prefix}/download?file=report-{{n}}.pdf",
            "dom_tpl": f"<a href='/{prefix}/download?file=report-{{n}}.pdf'>download</a>",
            "snippet_tpl": "application/pdf",
            "summary": f"{word} sample: download endpoint returns file content, not reflected HTML",
            "reason_type": "download_surface",
        },
        {
            "name": "file_upload_surface",
            "positive": False,
            "url_tpl": f"/{prefix}/upload/avatar/{{n}}",
            "dom_tpl": f"<form data-split='{word}'><input type='file' name='avatar'></form>",
            "snippet_tpl": "<input type='file' name='avatar'>",
            "summary": f"{word} sample: file upload surface without reflected user-controlled input",
            "reason_type": "file_upload_surface",
        },
        {
            "name": "api_no_reflection",
            "positive": False,
            "url_tpl": f"/{prefix}/api/status?{{param}}=test-{{n}}",
            "dom_tpl": "",
            "snippet_tpl": f'{{"split":"{word}","status":"ok"}}',
            "summary": f"{word} sample: API endpoint ignores parameter and does not reflect it",
            "reason_type": "api_no_reflection",
        },
        {
            "name": "redirect_no_reflection",
            "positive": False,
            "url_tpl": f"/{prefix}/login?next=/dashboard-{{n}}",
            "dom_tpl": "",
            "snippet_tpl": "302 Found",
            "summary": f"{word} sample: redirect flow without reflected HTML context",
            "reason_type": "redirect_without_reflection",
        },
    ]

    records: list[dict[str, Any]] = []

    for i in range(count):
        case = cases[i % len(cases)]
        param = PARAMS[i % len(PARAMS)]

        url = render_tpl(case["url_tpl"], param, i, split)
        dom = render_tpl(case["dom_tpl"], param, i, split)
        snippet = render_tpl(case["snippet_tpl"], param, i, split)

        payload = {
            "id": f"xss-clean-{split}-selection-{case['name']}-{i:04d}",
            "plugin": "xss",
            "agent": "xss_agent",
            "task": "selection",
            "context": {
                "url": url,
                "dom": dom,
                "sitemap_summary": case["summary"],
            },
            "evidence": {
                "response_snippet": snippet,
            },
        }

        if case["positive"]:
            assistant_json = {
                "plugin": "xss",
                "should_run": True,
                "confidence": case["confidence"],
                "injection_context": case["injection_context"],
                "parameter": param,
                "reason_type": case["reason_type"],
                "reason": f"User-controlled parameter '{param}' is reflected in {case['injection_context']} context.",
            }
        else:
            assistant_json = {
                "plugin": "xss",
                "should_run": False,
                "confidence": 30,
                "injection_context": "none",
                "parameter": param,
                "reason_type": case["reason_type"],
                "reason": f"XSS should not run because this is {case['reason_type']} without reflected executable context.",
            }

        records.append(make_record(payload["id"], "selection", instruction, payload, assistant_json))

    return records


def build_payload_planning_records(split: str, count: int) -> list[dict[str, Any]]:
    instruction = (
        "Generate an XSS payload planning object for this injection context. "
        "Return strict JSON only with keys: payloads, bypass_variants, strategy, context_notes."
    )

    cfg = SPLIT_CONFIG[split]
    prefix = cfg["prefix"]
    word = cfg["word"]

    cases = [
        {
            "context": "html_body",
            "dom_tpl": f"<p data-split='{word}'>test-{{n}}</p>",
            "payloads": ["<svg/onload=alert(1)>", "<img src=x onerror=alert(1)>"],
            "bypass_variants": ["%3Csvg%2Fonload%3Dalert%281%29%3E"],
            "strategy": "html body injection",
            "context_notes": "test whether HTML tags are interpreted or escaped",
        },
        {
            "context": "html_attribute",
            "dom_tpl": f"<input data-split='{word}' name='{{param}}' value='test-{{n}}'>",
            "payloads": ["\"><svg/onload=alert(1)>", "'><img src=x onerror=alert(1)>"],
            "bypass_variants": [
                "%22%3E%3Csvg%2Fonload%3Dalert%281%29%3E",
                "&#34;&#62;&#60;svg/onload=alert(1)&#62;",
            ],
            "strategy": "attribute breakout",
            "context_notes": "close quote before injecting a tag or event handler",
        },
        {
            "context": "js_string",
            "dom_tpl": f"<script>var {prefix}_{{param}}_{{n}} = \"test-{{n}}\";</script>",
            "payloads": ["\";alert(1);//", "';alert(1);//"],
            "bypass_variants": ["%22%3Balert%281%29%3B%2F%2F"],
            "strategy": "javascript string breakout",
            "context_notes": "close JavaScript string before scanner validation input",
        },
        {
            "context": "json_value",
            "dom_tpl": f'{{"split":"{word}","{{param}}":"test-{{n}}"}}',
            "payloads": ["\"><svg/onload=alert(1)>", "<img src=x onerror=alert(1)>"],
            "bypass_variants": [],
            "strategy": "json reflected value validation",
            "context_notes": "verify whether the reflected JSON value is later rendered into HTML or DOM",
        },
        {
            "context": "url_param",
            "dom_tpl": f"/{prefix}/reflect?{{param}}=test-{{n}}",
            "payloads": ["xss-test", "<svg/onload=alert(1)>"],
            "bypass_variants": ["%3Csvg%2Fonload%3Dalert%281%29%3E"],
            "strategy": "url parameter reflection check",
            "context_notes": f"{word} url parameter candidate: first verify reflection before escalating to context-specific payloads",
        },
    ]

    records: list[dict[str, Any]] = []

    for i in range(count):
        case = cases[i % len(cases)]
        param = PARAMS[(i * 3) % len(PARAMS)]
        dom = render_tpl(case["dom_tpl"], param, i, split)

        payload = {
            "id": f"xss-clean-{split}-payload-{case['context']}-{i:04d}",
            "plugin": "xss",
            "agent": "xss_agent",
            "task": "payload_planning",
            "context": {
                "plugin": "xss",
                "parameter": param,
                "injection_context": case["context"],
                "dom_snippet": dom,
            },
            "evidence": {
                "response_snippet": dom,
                "previous_attempts": [],
            },
        }

        assistant_json = {
            "payloads": case["payloads"],
            "bypass_variants": case["bypass_variants"],
            "strategy": case["strategy"],
            "context_notes": case["context_notes"],
        }

        records.append(make_record(payload["id"], "payload_planning", instruction, payload, assistant_json))

    return records


def build_false_positive_records(split: str, count: int) -> list[dict[str, Any]]:
    instruction = (
        "Decide whether this XSS finding is confirmed, likely false positive, or inconclusive. "
        "Return strict JSON only with keys: verdict, reason_type, reason, confidence."
    )

    cfg = SPLIT_CONFIG[split]
    word = cfg["word"]

    cases = [
        {
            "name": "confirmed_img_onerror",
            "verdict": "confirmed",
            "reason_type": "unescaped_executable_html",
            "evidence": "<img src=x onerror=alert(1)>",
            "response_tpl": f"<div data-split='{word}'><img src=x onerror=alert(1)></div>",
            "confidence": 82,
        },
        {
            "name": "confirmed_svg_onload",
            "verdict": "confirmed",
            "reason_type": "unescaped_executable_html",
            "evidence": "<svg/onload=alert(1)>",
            "response_tpl": f"<main data-split='{word}'><svg/onload=alert(1)></main>",
            "confidence": 82,
        },
        {
            "name": "confirmed_js_breakout",
            "verdict": "confirmed",
            "reason_type": "javascript_string_breakout",
            "evidence": "\";alert(1);//",
            "response_tpl": f"<script>var {split}_q=\"\";alert(1);//\";</script>",
            "confidence": 80,
        },
        {
            "name": "not_reflected",
            "verdict": "likely_false_positive",
            "reason_type": "not_reflected",
            "evidence": "<img src=x onerror=alert(1)>",
            "response_tpl": f"{word} search results: no matching result",
            "confidence": 76,
        },
        {
            "name": "html_escaped",
            "verdict": "likely_false_positive",
            "reason_type": "html_escaped",
            "evidence": "<script>alert(1)</script>",
            "response_tpl": f"{word} search: &lt;script&gt;alert(1)&lt;/script&gt;",
            "confidence": 76,
        },
        {
            "name": "comment_context",
            "verdict": "likely_false_positive",
            "reason_type": "inert_context",
            "evidence": "<svg/onload=alert(1)>",
            "response_tpl": f"<!-- {word}: <svg/onload=alert(1)> -->",
            "confidence": 74,
        },
        {
            "name": "textarea_context",
            "verdict": "likely_false_positive",
            "reason_type": "inert_context",
            "evidence": "<img src=x onerror=alert(1)>",
            "response_tpl": f"<textarea>{word}: <img src=x onerror=alert(1)></textarea>",
            "confidence": 74,
        },
        {
            "name": "code_context",
            "verdict": "likely_false_positive",
            "reason_type": "inert_context",
            "evidence": "<svg/onload=alert(1)>",
            "response_tpl": f"<code>{word}: <svg/onload=alert(1)></code>",
            "confidence": 74,
        },
        {
            "name": "attribute_reflection_only",
            "verdict": "inconclusive",
            "reason_type": "reflected_but_not_executable",
            "evidence": "xss-test",
            "response_tpl": f"<input data-split='{word}' value='xss-test'>",
            "confidence": 70,
        },
        {
            "name": "json_string_reflection_only",
            "verdict": "inconclusive",
            "reason_type": "reflected_but_not_executable",
            "evidence": "<img src=x onerror=alert(1)>",
            "response_tpl": f'{{"split":"{word}","query":"<img src=x onerror=alert(1)>"}}',
            "confidence": 70,
        },
    ]

    records: list[dict[str, Any]] = []

    for i in range(count):
        case = cases[i % len(cases)]

        payload = {
            "id": f"xss-clean-{split}-fp-{case['name']}-{i:04d}",
            "plugin": "xss",
            "agent": "xss_agent",
            "task": "false_positive",
            "context": {
                "finding": "Possible reflected XSS",
            },
            "evidence": {
                "evidence": case["evidence"],
                "response_body": render_tpl(case["response_tpl"], "q", i, split),
            },
        }

        assistant_json = {
            "verdict": case["verdict"],
            "reason_type": case["reason_type"],
            "confidence": case["confidence"],
            "reason": f"Expected verdict is {case['verdict']} because the evidence indicates {case['reason_type']}.",
        }

        records.append(make_record(payload["id"], "false_positive", instruction, payload, assistant_json))

    return records


def build_next_action_records(split: str, count: int) -> list[dict[str, Any]]:
    instruction = (
        "Suggest the next scanner action after XSS analysis. "
        "Return strict JSON only with keys: next_action, reason, priority."
    )

    cfg = SPLIT_CONFIG[split]
    word = cfg["word"]

    cases = [
        {
            "name": "stop_all_completed",
            "completed": ["xss", "csrf", "path_traversal", "jwt"],
            "findings": [{"plugin": "xss", "severity": "LOW", "title": f"{word} reflected XSS"}],
            "sitemap": f"{word} sample: all relevant plugins completed and no sensitive follow-up surface discovered",
            "next_action": "stop",
            "priority": "low",
        },
        {
            "name": "stop_low_signal",
            "completed": ["xss"],
            "findings": [{"plugin": "xss", "severity": "LOW", "title": f"{word} weak reflected input"}],
            "sitemap": f"{word} sample: static pages and public search only",
            "next_action": "stop",
            "priority": "low",
        },
        {
            "name": "csrf_followup",
            "completed": ["xss"],
            "findings": [{"plugin": "xss", "severity": "HIGH", "title": f"{word} reflected XSS"}],
            "sitemap": f"{word} sample: state-changing forms, cookie session, and admin route discovered",
            "next_action": "csrf",
            "priority": "medium",
        },
        {
            "name": "jwt_followup",
            "completed": ["xss"],
            "findings": [{"plugin": "xss", "severity": "CRITICAL", "title": f"{word} stored XSS"}],
            "sitemap": f"{word} sample: authorization bearer token and jwt api route discovered",
            "next_action": "jwt",
            "priority": "medium",
        },
        {
            "name": "continue_xss",
            "completed": ["selection"],
            "findings": [],
            "sitemap": f"{word} sample: reflected HTML body candidate discovered but XSS validation has not run yet",
            "next_action": "xss",
            "priority": "medium",
        },
    ]

    records: list[dict[str, Any]] = []

    for i in range(count):
        case = cases[i % len(cases)]

        payload = {
            "id": f"xss-clean-{split}-next-{case['name']}-{i:04d}",
            "plugin": "xss",
            "agent": "xss_agent",
            "task": "next_action",
            "context": {
                "completed": case["completed"],
                "findings": case["findings"],
                "sitemap": case["sitemap"],
            },
            "evidence": {},
        }

        assistant_json = {
            "next_action": case["next_action"],
            "priority": case["priority"],
            "reason": f"Expected follow-up action is {case['next_action']} based on completed checks, findings, and sitemap.",
        }

        records.append(make_record(payload["id"], "next_action", instruction, payload, assistant_json))

    return records


def validate_record(record: dict[str, Any]) -> None:
    task = record["task"]
    assistant = json.loads(record["messages"][2]["content"])
    expected = record["expected_json"]
    user_content = record["messages"][1]["content"]

    if expected != assistant:
        raise ValueError(f"expected_json and assistant output mismatch: {record['id']}")

    leftover_tokens = ["{{param}}", "{{n}}", "{{split}}", "{param}", "{n}", "{split}"]
    for token in leftover_tokens:
        if token in user_content:
            raise ValueError(f"template token remained in user content: {record['id']} token={token}")

    if task == "selection":
        required = {"plugin", "should_run", "confidence", "injection_context", "parameter", "reason_type", "reason"}
        if set(assistant) != required:
            raise ValueError(f"selection schema mismatch: {record['id']} -> {set(assistant)}")

        lowered = user_content.lower()
        if assistant["should_run"] is True:
            forbidden = [
                "no reflected",
                "without reflected",
                "does not reflect",
                "static asset",
                "file upload surface",
                "download endpoint",
                "302 found",
            ]
            for phrase in forbidden:
                if phrase in lowered:
                    raise ValueError(f"contradictory positive selection sample: {record['id']} contains {phrase}")

    if task == "false_positive":
        required = {"verdict", "reason_type", "confidence", "reason"}
        if set(assistant) != required:
            raise ValueError(f"false_positive schema mismatch: {record['id']} -> {set(assistant)}")

        if assistant["verdict"] == "confirmed":
            lowered = user_content.lower()
            forbidden = ["&lt;", "no matching result", "<!--", "<textarea>", "<code>"]
            for phrase in forbidden:
                if phrase in lowered:
                    raise ValueError(f"contradictory confirmed fp sample: {record['id']} contains {phrase}")

    if task == "next_action":
        required = {"next_action", "priority", "reason"}
        if set(assistant) != required:
            raise ValueError(f"next_action schema mismatch: {record['id']} -> {set(assistant)}")

        if assistant["next_action"] == "stop" and assistant["priority"] != "low":
            raise ValueError(f"stop action must be low priority: {record['id']}")

        if assistant["next_action"] in {"csrf", "jwt", "xss"} and assistant["priority"] not in {"medium", "high"}:
            raise ValueError(f"follow-up action priority should be medium/high: {record['id']}")

    if task == "payload_planning":
        required = {"payloads", "bypass_variants", "strategy", "context_notes"}
        if set(assistant) != required:
            raise ValueError(f"payload_planning schema mismatch: {record['id']} -> {set(assistant)}")


def task_distribution(records: list[dict[str, Any]]) -> dict[str, int]:
    dist: dict[str, int] = {}
    for r in records:
        dist[r["task"]] = dist.get(r["task"], 0) + 1
    return dict(sorted(dist.items()))


def build_split(split: str) -> list[dict[str, Any]]:
    count = SPLIT_CONFIG[split]["count_per_task"]

    records: list[dict[str, Any]] = []
    records.extend(build_selection_records(split, count))
    records.extend(build_payload_planning_records(split, count))
    records.extend(build_false_positive_records(split, count))
    records.extend(build_next_action_records(split, count))

    rng.shuffle(records)

    for r in records:
        validate_record(r)

    return records


def logical_key(record: dict[str, Any]) -> str:
    """
    Used only to confirm valid/test separation.
    Split-specific wording and URLs should make these different.
    """
    payload = json.loads(record["messages"][1]["content"].split("\n", 1)[1])
    expected = record["expected_json"]
    key_obj = {
        "task": record["task"],
        "payload_without_id": {
            k: v for k, v in payload.items() if k != "id"
        },
        "expected": expected,
    }
    return json.dumps(key_obj, ensure_ascii=False, sort_keys=True)


def main() -> None:
    train = build_split("train")
    valid = build_split("valid")
    test = build_split("test")

    raw = train + valid + test

    assert len(train) == 1800
    assert len(valid) == 300
    assert len(test) == 300
    assert len(raw) == 2400

    all_ids = [r["id"] for r in raw]
    if len(all_ids) != len(set(all_ids)):
        raise ValueError("duplicate IDs detected")

    valid_keys = {logical_key(r) for r in valid}
    test_keys = {logical_key(r) for r in test}
    overlap = valid_keys & test_keys
    if overlap:
        raise ValueError(f"valid/test logical overlap detected: {len(overlap)}")

    OUT_DIR.mkdir(parents=True, exist_ok=True)

    write_jsonl(OUT_RAW, raw)
    write_jsonl(OUT_TRAIN, train)
    write_jsonl(OUT_VALID, valid)
    write_jsonl(OUT_TEST, test)

    report = {
        "seed": SEED,
        "total": len(raw),
        "train": len(train),
        "valid": len(valid),
        "test": len(test),
        "raw_distribution": task_distribution(raw),
        "train_distribution": task_distribution(train),
        "valid_distribution": task_distribution(valid),
        "test_distribution": task_distribution(test),
        "fixes": {
            "json_value_double_braces": "removed by using render_tpl() with direct placeholder replacement only",
            "expected_assistant_schema": "expected_json and assistant content are identical for every record",
            "valid_test_overlap": "train/valid/test are generated with split-specific URLs, DOM snippets, sitemap wording, and response markers",
        },
        "policy": {
            "selection": {
                "positive": "should_run=true only when user-controlled input is reflected in DOM/response or JSON value with client-rendering risk",
                "negative": "should_run=false for static assets, download/file upload surfaces, API no-reflection, and redirect without reflection",
            },
            "false_positive": {
                "confirmed": "unescaped executable HTML or JavaScript string breakout is present in response_body",
                "likely_false_positive": "not reflected, HTML escaped, or inert context",
                "inconclusive": "reflected but not clearly executable",
            },
            "next_action": {
                "stop_low": "completed all or low-signal only -> stop / low",
                "csrf": "state-changing forms/admin/cookie session -> csrf / medium",
                "jwt": "bearer token or JWT API route -> jwt / medium",
                "xss": "XSS validation has not yet run for reflected candidate -> xss / medium",
            },
            "payload_planning": {
                "rule": "payloads must match injection context, not only generic script tags",
            },
        },
    }

    write_json(OUT_REPORT, report)

    print("=== XSS clean dataset rebuilt ===")
    print(f"raw   : {len(raw)} -> {OUT_RAW}")
    print(f"train : {len(train)} -> {OUT_TRAIN}")
    print(f"valid : {len(valid)} -> {OUT_VALID}")
    print(f"test  : {len(test)} -> {OUT_TEST}")
    print(f"report: {OUT_REPORT}")
    print()
    print("raw_distribution  :", task_distribution(raw))
    print("train_distribution:", task_distribution(train))
    print("valid_distribution:", task_distribution(valid))
    print("test_distribution :", task_distribution(test))
    print("valid/test logical overlap:", len(overlap))


if __name__ == "__main__":
    main()
