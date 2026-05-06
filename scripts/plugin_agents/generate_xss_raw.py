from __future__ import annotations

import argparse
import json
import random
from pathlib import Path
from typing import Any

from _utils import write_jsonl


DEFAULT_OUT = Path("data/plugin_agents/xss/raw.jsonl")

PARAMETERS = [
    "q",
    "query",
    "keyword",
    "search",
    "name",
    "title",
    "comment",
    "body",
    "bio",
    "term",
]

ENDPOINTS = [
    "/search",
    "/lookup",
    "/profile",
    "/items",
    "/comments",
    "/products",
    "/users",
    "/posts",
    "/filter",
    "/results",
]


def make_record(
    *,
    sample_id: str,
    task: str,
    context: dict[str, Any],
    evidence: dict[str, Any],
    expected_json: dict[str, Any],
) -> dict[str, Any]:
    return {
        "id": sample_id,
        "plugin": "xss",
        "agent": "xss_agent",
        "task": task,
        "context": context,
        "evidence": evidence,
        "expected_json": expected_json,
    }


def generate_selection_cases(count: int, rng: random.Random) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []

    contexts = [
        "html_attribute",
        "html_body",
        "js_string",
        "json_value",
        "url_param",
        "negative",
    ]

    attribute_templates = [
        '<input name="{param}" value="test">',
        '<a title="test" href="/items">item</a>',
        '<img src="/static/a.png" alt="test">',
        '<div data-{param}="test">result</div>',
        '<button aria-label="test">submit</button>',
    ]

    body_templates = [
        "<p>Search result: test</p>",
        '<div class="comment">test</div>',
        '<section class="bio">test</section>',
        "<span>test</span>",
        "<h1>test</h1>",
    ]

    js_templates = [
        '<script>var {param} = "test";</script>',
        "<script>const {param} = 'test';</script>",
        '<script>window.__{param} = "test";</script>',
        '<script>let searchValue = "test";</script>',
    ]

    json_templates = [
        '{{"{param}":"test","results":[]}}',
        '{{"status":"ok","{param}":"test"}}',
        '{{"data":{{"{param}":"test"}}}}',
    ]

    negative_templates = [
        {
            "url": "/login",
            "dom": '<form><input type="password" name="password"></form>',
            "response_snippet": "",
            "reason_type": "login_form_only",
        },
        {
            "url": "/static/app.js",
            "dom": "",
            "response_snippet": "function app() { return true; }",
            "reason_type": "static_asset",
        },
        {
            "url": "/static/logo.png",
            "dom": "",
            "response_snippet": "",
            "reason_type": "static_asset",
        },
        {
            "url": "/download?file=report.pdf",
            "dom": "<a href='/download?file=report.pdf'>download</a>",
            "response_snippet": "application/pdf",
            "reason_type": "path_traversal_or_download_surface",
        },
        {
            "url": "/upload",
            "dom": '<form><input type="file" name="avatar"></form>',
            "response_snippet": '<input type="file" name="avatar">',
            "reason_type": "file_upload_surface",
        },
    ]

    counts_per_context: dict[str, int] = {c: 0 for c in contexts}

    for idx in range(count):
        context_type = contexts[idx % len(contexts)]
        param = rng.choice(PARAMETERS)
        endpoint = rng.choice(ENDPOINTS)
        counts_per_context[context_type] += 1
        sample_no = counts_per_context[context_type]

        if context_type == "html_attribute":
            dom = rng.choice(attribute_templates).format(param=param)
            url = f"{endpoint}?{param}=test"
            records.append(
                make_record(
                    sample_id=f"xss-selection-html-attribute-{sample_no:04d}",
                    task="selection",
                    context={
                        "url": url,
                        "dom": dom,
                        "sitemap_summary": f"{param} parameter is reflected in an HTML attribute",
                    },
                    evidence={"response_snippet": dom},
                    expected_json={
                        "plugin": "xss",
                        "should_run": True,
                        "confidence_min": 70,
                        "injection_context": "html_attribute",
                        "parameter": param,
                    },
                )
            )
            continue

        if context_type == "html_body":
            dom = rng.choice(body_templates)
            url = f"{endpoint}?{param}=test"
            records.append(
                make_record(
                    sample_id=f"xss-selection-html-body-{sample_no:04d}",
                    task="selection",
                    context={
                        "url": url,
                        "dom": dom,
                        "sitemap_summary": "user input is reflected in HTML body text",
                    },
                    evidence={"response_snippet": dom},
                    expected_json={
                        "plugin": "xss",
                        "should_run": True,
                        "confidence_min": 70,
                        "injection_context": "html_body",
                        "parameter": param,
                    },
                )
            )
            continue

        if context_type == "js_string":
            dom = rng.choice(js_templates).format(param=param)
            url = f"{endpoint}?{param}=test"
            records.append(
                make_record(
                    sample_id=f"xss-selection-js-string-{sample_no:04d}",
                    task="selection",
                    context={
                        "url": url,
                        "dom": dom,
                        "sitemap_summary": "user input is reflected inside a JavaScript string",
                    },
                    evidence={"response_snippet": dom},
                    expected_json={
                        "plugin": "xss",
                        "should_run": True,
                        "confidence_min": 70,
                        "injection_context": "js_string",
                        "parameter": param,
                    },
                )
            )
            continue

        if context_type == "json_value":
            response_snippet = rng.choice(json_templates).format(param=param)
            url = f"/api{endpoint}?{param}=test"
            records.append(
                make_record(
                    sample_id=f"xss-selection-json-value-{sample_no:04d}",
                    task="selection",
                    context={
                        "url": url,
                        "dom": "",
                        "sitemap_summary": "user input is reflected in a JSON response value",
                    },
                    evidence={"response_snippet": response_snippet},
                    expected_json={
                        "plugin": "xss",
                        "should_run": True,
                        "confidence_min": 60,
                        "injection_context": "json_value",
                        "parameter": param,
                    },
                )
            )
            continue

        if context_type == "url_param":
            url = f"{endpoint}?{param}=test"
            records.append(
                make_record(
                    sample_id=f"xss-selection-url-param-{sample_no:04d}",
                    task="selection",
                    context={
                        "url": url,
                        "dom": "",
                        "sitemap_summary": "URL parameter exists but response reflection evidence is missing",
                    },
                    evidence={"response_snippet": ""},
                    expected_json={
                        "plugin": "xss",
                        "should_run": True,
                        "confidence_min": 50,
                        "injection_context": "url_param",
                        "parameter": param,
                    },
                )
            )
            continue

        negative = rng.choice(negative_templates)
        records.append(
            make_record(
                sample_id=f"xss-selection-negative-{sample_no:04d}",
                task="selection",
                context={
                    "url": negative["url"],
                    "dom": negative["dom"],
                    "sitemap_summary": "no reliable reflected user-controlled input for XSS",
                },
                evidence={"response_snippet": negative["response_snippet"]},
                expected_json={
                    "plugin": "xss",
                    "should_run": False,
                    "confidence_max": 60,
                    "reason_type": negative["reason_type"],
                },
            )
        )

    return records


def generate_payload_cases(count: int, rng: random.Random) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []

    payload_specs = [
        {
            "context": "html_attribute",
            "payloads": ['"><svg/onload=alert(1)>', "'><img src=x onerror=alert(1)>"],
            "bypass_variants": [
                "%22%3E%3Csvg%2Fonload%3Dalert%281%29%3E",
                "&#34;&#62;&#60;svg/onload=alert(1)&#62;",
            ],
            "strategy": "attribute breakout",
            "context_notes": "close quote before injecting a tag or event handler",
            "dom_template": '<input name="{param}" value="test">',
        },
        {
            "context": "html_body",
            "payloads": ["<svg/onload=alert(1)>", "<img src=x onerror=alert(1)>"],
            "bypass_variants": ["%3Csvg%2Fonload%3Dalert%281%29%3E"],
            "strategy": "html body injection",
            "context_notes": "test whether HTML tags are interpreted or escaped",
            "dom_template": "<p>test</p>",
        },
        {
            "context": "js_string",
            "payloads": ['";alert(1);//', "';alert(1);//"],
            "bypass_variants": ["%22%3Balert%281%29%3B%2F%2F"],
            "strategy": "javascript string breakout",
            "context_notes": "close JavaScript string before scanner validation input",
            "dom_template": '<script>var {param} = "test";</script>',
        },
        {
            "context": "json_value",
            "payloads": ['"><svg/onload=alert(1)>', "<img src=x onerror=alert(1)>"],
            "bypass_variants": [],
            "strategy": "json reflected value validation",
            "context_notes": "verify whether the reflected JSON value is later rendered into HTML or DOM",
            "dom_template": '{{"{param}":"test"}}',
        },
        {
            "context": "url_param",
            "payloads": ["xss-test", "<svg/onload=alert(1)>"],
            "bypass_variants": ["%3Csvg%2Fonload%3Dalert%281%29%3E"],
            "strategy": "url parameter reflection check",
            "context_notes": "first verify reflection before escalating to context-specific payloads",
            "dom_template": "",
        },
    ]

    counts_per_context: dict[str, int] = {}

    for idx in range(count):
        spec = payload_specs[idx % len(payload_specs)]
        param = rng.choice(PARAMETERS)
        dom_snippet = spec["dom_template"].format(param=param) if spec["dom_template"] else ""
        counts_per_context[spec["context"]] = counts_per_context.get(spec["context"], 0) + 1
        sample_no = counts_per_context[spec["context"]]

        records.append(
            make_record(
                sample_id=f"xss-payload-{spec['context']}-{sample_no:04d}",
                task="payload_planning",
                context={
                    "plugin": "xss",
                    "parameter": param,
                    "injection_context": spec["context"],
                    "dom_snippet": dom_snippet,
                },
                evidence={
                    "response_snippet": dom_snippet,
                    "previous_attempts": [],
                },
                expected_json={
                    "payloads": spec["payloads"],
                    "bypass_variants": spec["bypass_variants"],
                    "strategy": spec["strategy"],
                    "context_notes": spec["context_notes"],
                },
            )
        )

    return records


def generate_false_positive_cases(count: int, rng: random.Random) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []

    fp_specs = [
        {
            "name": "confirmed_unescaped_svg",
            "evidence": "<svg/onload=alert(1)>",
            "response_body": "Search results: <svg/onload=alert(1)>",
            "verdict": "confirmed",
            "reason_type": "unescaped_executable_html",
        },
        {
            "name": "confirmed_img_onerror",
            "evidence": "<img src=x onerror=alert(1)>",
            "response_body": "<div><img src=x onerror=alert(1)></div>",
            "verdict": "confirmed",
            "reason_type": "unescaped_executable_html",
        },
        {
            "name": "escaped_script",
            "evidence": "<script>alert(1)</script>",
            "response_body": "Search: &lt;script&gt;alert(1)&lt;/script&gt;",
            "verdict": "likely_false_positive",
            "reason_type": "html_escaped",
        },
        {
            "name": "escaped_svg",
            "evidence": "<svg/onload=alert(1)>",
            "response_body": "Search: &lt;svg/onload=alert(1)&gt;",
            "verdict": "likely_false_positive",
            "reason_type": "html_escaped",
        },
        {
            "name": "not_reflected",
            "evidence": "<img src=x onerror=alert(1)>",
            "response_body": "Search results: no matching result",
            "verdict": "likely_false_positive",
            "reason_type": "not_reflected",
        },
        {
            "name": "inert_code_context",
            "evidence": "<svg/onload=alert(1)>",
            "response_body": "<code><svg/onload=alert(1)></code>",
            "verdict": "likely_false_positive",
            "reason_type": "inert_context",
        },
        {
            "name": "inert_textarea_context",
            "evidence": "<img src=x onerror=alert(1)>",
            "response_body": "<textarea><img src=x onerror=alert(1)></textarea>",
            "verdict": "likely_false_positive",
            "reason_type": "inert_context",
        },
        {
            "name": "comment_context",
            "evidence": "<svg/onload=alert(1)>",
            "response_body": "<!-- <svg/onload=alert(1)> -->",
            "verdict": "likely_false_positive",
            "reason_type": "inert_context",
        },
        {
            "name": "plain_reflection",
            "evidence": "xss-test",
            "response_body": "Search results: xss-test",
            "verdict": "inconclusive",
            "reason_type": "reflected_but_not_executable",
        },
        {
            "name": "attribute_reflection_only",
            "evidence": "xss-test",
            "response_body": '<input value="xss-test">',
            "verdict": "inconclusive",
            "reason_type": "reflected_but_not_executable",
        },
    ]

    counts_per_name: dict[str, int] = {}

    for idx in range(count):
        spec = fp_specs[idx % len(fp_specs)]
        counts_per_name[spec["name"]] = counts_per_name.get(spec["name"], 0) + 1
        sample_no = counts_per_name[spec["name"]]

        records.append(
            make_record(
                sample_id=f"xss-fp-{spec['name']}-{sample_no:04d}",
                task="false_positive",
                context={"finding": "Possible reflected XSS"},
                evidence={
                    "evidence": spec["evidence"],
                    "response_body": spec["response_body"],
                },
                expected_json={
                    "verdict": spec["verdict"],
                    "reason_type": spec["reason_type"],
                    "confidence_min": 70,
                },
            )
        )

    return records


def generate_next_action_cases(count: int, rng: random.Random) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []

    next_specs = [
        {
            "name": "xss_to_csrf",
            "completed": ["xss"],
            "findings": [{"plugin": "xss", "severity": "HIGH", "title": "Reflected XSS"}],
            "sitemap": "state-changing forms and admin route discovered",
            "next_action": "csrf",
            "priority": "medium",
        },
        {
            "name": "xss_to_path",
            "completed": ["xss"],
            "findings": [{"plugin": "xss", "severity": "HIGH", "title": "Reflected XSS"}],
            "sitemap": "admin panel and file download route discovered",
            "next_action": "path_traversal",
            "priority": "medium",
        },
        {
            "name": "xss_to_jwt",
            "completed": ["xss"],
            "findings": [{"plugin": "xss", "severity": "CRITICAL", "title": "Stored XSS"}],
            "sitemap": "authorization bearer token and jwt api route discovered",
            "next_action": "jwt",
            "priority": "medium",
        },
        {
            "name": "xss_stop_all_completed",
            "completed": ["xss", "csrf", "path_traversal", "jwt"],
            "findings": [{"plugin": "xss", "severity": "LOW", "title": "Reflected XSS"}],
            "sitemap": "no sensitive follow-up surface discovered",
            "next_action": "stop",
            "priority": "low",
        },
        {
            "name": "xss_stop_low_signal",
            "completed": ["xss"],
            "findings": [{"plugin": "xss", "severity": "LOW", "title": "Weak reflected input"}],
            "sitemap": "static pages and public search only",
            "next_action": "stop",
            "priority": "low",
        },
    ]

    counts_per_name: dict[str, int] = {}

    for idx in range(count):
        spec = next_specs[idx % len(next_specs)]
        counts_per_name[spec["name"]] = counts_per_name.get(spec["name"], 0) + 1
        sample_no = counts_per_name[spec["name"]]

        records.append(
            make_record(
                sample_id=f"xss-next-{spec['name']}-{sample_no:04d}",
                task="next_action",
                context={
                    "completed": spec["completed"],
                    "findings": spec["findings"],
                    "sitemap": spec["sitemap"],
                },
                evidence={},
                expected_json={
                    "next_action": spec["next_action"],
                    "priority": spec["priority"],
                },
            )
        )

    return records


def resolve_counts(total: int | None) -> dict[str, int]:
    if total is None:
        total = 1000

    if total <= 0:
        raise ValueError("--total must be positive")

    ratios = {
        "selection": 0.30,
        "payload_planning": 0.25,
        "false_positive": 0.30,
        "next_action": 0.15,
    }

    counts = {task: int(total * ratio) for task, ratio in ratios.items()}
    diff = total - sum(counts.values())

    order = ["selection", "false_positive", "payload_planning", "next_action"]
    for idx in range(diff):
        counts[order[idx % len(order)]] += 1

    return counts


def generate_records(
    total: int | None = None,
    limit: int | None = None,
    seed: int = 42,
) -> list[dict[str, Any]]:
    counts = resolve_counts(total)
    rng = random.Random(seed)

    records: list[dict[str, Any]] = []
    records.extend(generate_selection_cases(counts["selection"], rng))
    records.extend(generate_payload_cases(counts["payload_planning"], rng))
    records.extend(generate_false_positive_cases(counts["false_positive"], rng))
    records.extend(generate_next_action_cases(counts["next_action"], rng))

    if limit is not None:
        records = records[:limit]

    return records


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate synthetic raw samples for XSSAgent evaluation.")
    parser.add_argument("--out", default=str(DEFAULT_OUT))
    parser.add_argument("--total", type=int, default=None, help="Total sample count (default: 1000)")
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    records = generate_records(total=args.total, limit=args.limit, seed=args.seed)
    write_jsonl(records, Path(args.out))

    by_task: dict[str, int] = {}
    for record in records:
        by_task[record["task"]] = by_task.get(record["task"], 0) + 1

    print(f"wrote {len(records)} records to {args.out}")
    print(json.dumps({"by_task": by_task}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
