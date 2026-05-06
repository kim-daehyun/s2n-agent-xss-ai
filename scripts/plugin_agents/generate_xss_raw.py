from __future__ import annotations

import argparse
import json
from pathlib import Path


DEFAULT_OUT = Path("data/plugin_agents/xss/raw.jsonl")


def make_record(
    *,
    sample_id: str,
    task: str,
    context: dict,
    evidence: dict,
    expected_json: dict,
) -> dict:
    return {
        "id": sample_id,
        "plugin": "xss",
        "agent": "xss_agent",
        "task": task,
        "context": context,
        "evidence": evidence,
        "expected_json": expected_json,
    }


def generate_selection_cases() -> list[dict]:
    records: list[dict] = []

    html_attribute_cases = [
        {
            "name": "search_q_input_value",
            "url": "/search?q=test",
            "parameter": "q",
            "dom": '<input name="q" value="test">',
            "response_snippet": '<input name="q" value="test">',
        },
        {
            "name": "profile_name_input_value",
            "url": "/profile?name=test",
            "parameter": "name",
            "dom": '<input name="name" value="test">',
            "response_snippet": '<input name="name" value="test">',
        },
        {
            "name": "item_title_attribute",
            "url": "/items?title=test",
            "parameter": "title",
            "dom": '<a title="test" href="/items">item</a>',
            "response_snippet": '<a title="test" href="/items">item</a>',
        },
        {
            "name": "image_alt_attribute",
            "url": "/gallery?alt=test",
            "parameter": "alt",
            "dom": '<img src="/static/a.png" alt="test">',
            "response_snippet": '<img src="/static/a.png" alt="test">',
        },
        {
            "name": "data_query_attribute",
            "url": "/lookup?query=test",
            "parameter": "query",
            "dom": '<div data-query="test">result</div>',
            "response_snippet": '<div data-query="test">result</div>',
        },
    ]

    for idx, case in enumerate(html_attribute_cases, start=1):
        records.append(
            make_record(
                sample_id=f"xss-selection-html-attribute-{idx:03d}",
                task="selection",
                context={
                    "url": case["url"],
                    "dom": case["dom"],
                    "sitemap_summary": f"{case['parameter']} parameter is reflected in an HTML attribute",
                },
                evidence={
                    "response_snippet": case["response_snippet"],
                },
                expected_json={
                    "plugin": "xss",
                    "should_run": True,
                    "confidence_min": 70,
                    "injection_context": "html_attribute",
                    "parameter": case["parameter"],
                },
            )
        )

    html_body_cases = [
        {
            "name": "search_result_body",
            "url": "/search?q=test",
            "parameter": "q",
            "dom": "<p>Search result: test</p>",
            "response_snippet": "<p>Search result: test</p>",
        },
        {
            "name": "comment_body",
            "url": "/comments?body=test",
            "parameter": "body",
            "dom": '<div class="comment">test</div>',
            "response_snippet": '<div class="comment">test</div>',
        },
        {
            "name": "profile_bio_body",
            "url": "/profile?bio=test",
            "parameter": "bio",
            "dom": '<section class="bio">test</section>',
            "response_snippet": '<section class="bio">test</section>',
        },
    ]

    for idx, case in enumerate(html_body_cases, start=1):
        records.append(
            make_record(
                sample_id=f"xss-selection-html-body-{idx:03d}",
                task="selection",
                context={
                    "url": case["url"],
                    "dom": case["dom"],
                    "sitemap_summary": "user input is reflected in HTML body text",
                },
                evidence={
                    "response_snippet": case["response_snippet"],
                },
                expected_json={
                    "plugin": "xss",
                    "should_run": True,
                    "confidence_min": 70,
                    "injection_context": "html_body",
                    "parameter": case["parameter"],
                },
            )
        )

    js_string_cases = [
        {
            "name": "script_var_q",
            "url": "/search?q=test",
            "parameter": "q",
            "dom": '<script>var q = "test";</script>',
            "response_snippet": '<script>var q = "test";</script>',
        },
        {
            "name": "script_keyword",
            "url": "/search?keyword=test",
            "parameter": "keyword",
            "dom": "<script>const keyword = 'test';</script>",
            "response_snippet": "<script>const keyword = 'test';</script>",
        },
    ]

    for idx, case in enumerate(js_string_cases, start=1):
        records.append(
            make_record(
                sample_id=f"xss-selection-js-string-{idx:03d}",
                task="selection",
                context={
                    "url": case["url"],
                    "dom": case["dom"],
                    "sitemap_summary": "user input is reflected inside a JavaScript string",
                },
                evidence={
                    "response_snippet": case["response_snippet"],
                },
                expected_json={
                    "plugin": "xss",
                    "should_run": True,
                    "confidence_min": 70,
                    "injection_context": "js_string",
                    "parameter": case["parameter"],
                },
            )
        )

    json_value_cases = [
        {
            "name": "api_search_json",
            "url": "/api/search?q=test",
            "parameter": "q",
            "dom": "",
            "response_snippet": '{"query":"test","results":[]}',
        },
        {
            "name": "api_profile_json",
            "url": "/api/profile?name=test",
            "parameter": "name",
            "dom": "",
            "response_snippet": '{"name":"test","status":"ok"}',
        },
    ]

    for idx, case in enumerate(json_value_cases, start=1):
        records.append(
            make_record(
                sample_id=f"xss-selection-json-value-{idx:03d}",
                task="selection",
                context={
                    "url": case["url"],
                    "dom": case["dom"],
                    "sitemap_summary": "user input is reflected in a JSON response value",
                },
                evidence={
                    "response_snippet": case["response_snippet"],
                },
                expected_json={
                    "plugin": "xss",
                    "should_run": True,
                    "confidence_min": 60,
                    "injection_context": "json_value",
                    "parameter": case["parameter"],
                },
            )
        )

    url_param_cases = [
        {
            "name": "url_only_q",
            "url": "/search?q=test",
            "parameter": "q",
            "dom": "",
            "response_snippet": "",
        },
        {
            "name": "url_only_keyword",
            "url": "/lookup?keyword=test",
            "parameter": "keyword",
            "dom": "",
            "response_snippet": "",
        },
    ]

    for idx, case in enumerate(url_param_cases, start=1):
        records.append(
            make_record(
                sample_id=f"xss-selection-url-param-{idx:03d}",
                task="selection",
                context={
                    "url": case["url"],
                    "dom": case["dom"],
                    "sitemap_summary": "URL parameter exists but response reflection evidence is missing",
                },
                evidence={
                    "response_snippet": case["response_snippet"],
                },
                expected_json={
                    "plugin": "xss",
                    "should_run": True,
                    "confidence_min": 50,
                    "injection_context": "url_param",
                    "parameter": case["parameter"],
                },
            )
        )

    negative_cases = [
        {
            "name": "login_password_only",
            "url": "/login",
            "dom": '<form><input type="password" name="password"></form>',
            "response_snippet": "",
            "reason_type": "login_form_only",
        },
        {
            "name": "static_js",
            "url": "/static/app.js",
            "dom": "",
            "response_snippet": "function app() { return true; }",
            "reason_type": "static_asset",
        },
        {
            "name": "image_asset",
            "url": "/static/logo.png",
            "dom": "",
            "response_snippet": "",
            "reason_type": "static_asset",
        },
        {
            "name": "file_download",
            "url": "/download?file=report.pdf",
            "dom": "<a href='/download?file=report.pdf'>download</a>",
            "response_snippet": "application/pdf",
            "reason_type": "path_traversal_or_download_surface",
        },
        {
            "name": "upload_form",
            "url": "/upload",
            "dom": '<form><input type="file" name="avatar"></form>',
            "response_snippet": '<input type="file" name="avatar">',
            "reason_type": "file_upload_surface",
        },
    ]

    for idx, case in enumerate(negative_cases, start=1):
        records.append(
            make_record(
                sample_id=f"xss-selection-negative-{idx:03d}",
                task="selection",
                context={
                    "url": case["url"],
                    "dom": case["dom"],
                    "sitemap_summary": "no reliable reflected user-controlled input for XSS",
                },
                evidence={
                    "response_snippet": case["response_snippet"],
                },
                expected_json={
                    "plugin": "xss",
                    "should_run": False,
                    "confidence_max": 60,
                    "reason_type": case["reason_type"],
                },
            )
        )

    return records


def generate_payload_cases() -> list[dict]:
    cases = [
        {
            "context": "html_attribute",
            "parameter": "q",
            "dom_snippet": '<input name="q" value="test">',
            "payloads": ['"><svg/onload=alert(1)>', "'><img src=x onerror=alert(1)>"],
            "bypass_variants": [
                "%22%3E%3Csvg%2Fonload%3Dalert%281%29%3E",
                "&#34;&#62;&#60;svg/onload=alert(1)&#62;",
            ],
            "strategy": "attribute breakout",
            "context_notes": "close quote before injecting a tag or event handler",
        },
        {
            "context": "html_body",
            "parameter": "q",
            "dom_snippet": "<p>test</p>",
            "payloads": ["<svg/onload=alert(1)>", "<img src=x onerror=alert(1)>"],
            "bypass_variants": ["%3Csvg%2Fonload%3Dalert%281%29%3E"],
            "strategy": "html body injection",
            "context_notes": "test whether HTML tags are interpreted or escaped",
        },
        {
            "context": "js_string",
            "parameter": "q",
            "dom_snippet": '<script>var q = "test";</script>',
            "payloads": ['";alert(1);//', "';alert(1);//"],
            "bypass_variants": ["%22%3Balert%281%29%3B%2F%2F"],
            "strategy": "javascript string breakout",
            "context_notes": "close JavaScript string before scanner validation input",
        },
        {
            "context": "json_value",
            "parameter": "q",
            "dom_snippet": '{"query":"test"}',
            "payloads": ['"><svg/onload=alert(1)>', "<img src=x onerror=alert(1)>"],
            "bypass_variants": [],
            "strategy": "json reflected value validation",
            "context_notes": "verify whether the reflected JSON value is later rendered into HTML or DOM",
        },
        {
            "context": "url_param",
            "parameter": "q",
            "dom_snippet": "",
            "payloads": ["xss-test", "<svg/onload=alert(1)>"],
            "bypass_variants": ["%3Csvg%2Fonload%3Dalert%281%29%3E"],
            "strategy": "url parameter reflection check",
            "context_notes": "first verify reflection before escalating to context-specific payloads",
        },
    ]

    records: list[dict] = []
    for idx, case in enumerate(cases, start=1):
        records.append(
            make_record(
                sample_id=f"xss-payload-{case['context']}-{idx:03d}",
                task="payload_planning",
                context={
                    "plugin": "xss",
                    "parameter": case["parameter"],
                    "injection_context": case["context"],
                    "dom_snippet": case["dom_snippet"],
                },
                evidence={
                    "response_snippet": case["dom_snippet"],
                    "previous_attempts": [],
                },
                expected_json={
                    "payloads": case["payloads"],
                    "bypass_variants": case["bypass_variants"],
                    "strategy": case["strategy"],
                    "context_notes": case["context_notes"],
                },
            )
        )

    return records


def generate_false_positive_cases() -> list[dict]:
    cases = [
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
            "name": "inconclusive_reflection",
            "evidence": "xss-test",
            "response_body": "Search results: xss-test",
            "verdict": "inconclusive",
            "reason_type": "reflected_but_not_executable",
        },
    ]

    records: list[dict] = []
    for idx, case in enumerate(cases, start=1):
        records.append(
            make_record(
                sample_id=f"xss-fp-{case['name']}-{idx:03d}",
                task="false_positive",
                context={
                    "finding": "Possible reflected XSS",
                },
                evidence={
                    "evidence": case["evidence"],
                    "response_body": case["response_body"],
                },
                expected_json={
                    "verdict": case["verdict"],
                    "reason_type": case["reason_type"],
                    "confidence_min": 70,
                },
            )
        )

    return records


def generate_next_action_cases() -> list[dict]:
    cases = [
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
            "name": "xss_stop",
            "completed": ["xss", "csrf", "path_traversal", "jwt"],
            "findings": [{"plugin": "xss", "severity": "LOW", "title": "Reflected XSS"}],
            "sitemap": "no sensitive follow-up surface discovered",
            "next_action": "stop",
            "priority": "low",
        },
    ]

    records: list[dict] = []
    for idx, case in enumerate(cases, start=1):
        records.append(
            make_record(
                sample_id=f"xss-next-{case['name']}-{idx:03d}",
                task="next_action",
                context={
                    "completed": case["completed"],
                    "findings": case["findings"],
                    "sitemap": case["sitemap"],
                },
                evidence={},
                expected_json={
                    "next_action": case["next_action"],
                    "priority": case["priority"],
                },
            )
        )

    return records


def generate_records(limit: int | None = None) -> list[dict]:
    records: list[dict] = []
    records.extend(generate_selection_cases())
    records.extend(generate_payload_cases())
    records.extend(generate_false_positive_cases())
    records.extend(generate_next_action_cases())

    if limit is not None:
        records = records[:limit]

    return records


def write_jsonl(records: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate synthetic raw samples for XSSAgent evaluation.")
    parser.add_argument("--out", default=str(DEFAULT_OUT))
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args()

    records = generate_records(limit=args.limit)
    write_jsonl(records, Path(args.out))

    print(f"wrote {len(records)} records to {args.out}")


if __name__ == "__main__":
    main()