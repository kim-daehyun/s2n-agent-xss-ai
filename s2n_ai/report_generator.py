from pathlib import Path
from datetime import datetime
from typing import Any, Dict, List, Tuple
import re


FENCE = "`" * 3


def _safe(value: Any, default: str = "-") -> str:
    if value is None:
        return default
    if value == "":
        return default
    return str(value)


def _as_dict(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _evidence_get(evidence: Any, key: str, default: Any = None) -> Any:
    """Safely read evidence whether it is a dict or a string.

    Old report_generator expected evidence to be a dict.
    Current normalizer can provide evidence as a raw string, so this function
    prevents: AttributeError: 'str' object has no attribute 'get'
    """
    if isinstance(evidence, dict):
        return _evidence_get(evidence, key, default)

    text = "" if evidence is None else str(evidence)
    lower = text.lower()

    if key in ("reflection", "reflected", "reflection_detected", "detected"):
        markers = [
            "reflected in http response",
            "payload reflected",
            "payload already present",
            "direct_url_payload_reflected",
            "verification=payload_reflected",
            "verification=direct_url_payload_reflected",
            "without clear output encoding",
            "reflected_value=",
            "was reflected",
        ]
        return any(marker in lower for marker in markers)

    if key in ("reflected_value", "payload"):
        for marker in ("reflected_value=", "payload="):
            if marker in text:
                return text.split(marker, 1)[1].split(";", 1)[0].strip()
        return default

    if key in ("verification", "verified"):
        if "direct_url_payload_reflected" in lower:
            return "direct_url_payload_reflected"
        if "verification=payload_reflected" in lower or "payload reflected" in lower:
            return "payload_reflected"
        if "reflected in http response" in lower:
            return "payload_reflected"
        return default

    if key in ("response_snippet", "snippet", "body", "raw"):
        return text if text else default

    return default


def _escape_pipe(value: Any) -> str:
    return _safe(value).replace("|", "\\|").replace("\n", "<br>")


def _make_table(rows: List[Tuple[str, Any]]) -> str:
    lines = [
        "| Field | Value |",
        "|---|---|",
    ]

    for key, value in rows:
        lines.append(f"| **{_escape_pipe(key)}** | {_escape_pipe(value)} |")

    return "\n".join(lines)


def _split_contexts(
    rag_contexts: List[Dict[str, Any]],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    internal_contexts: List[Dict[str, Any]] = []
    external_references: List[Dict[str, Any]] = []

    for ctx in rag_contexts or []:
        if not isinstance(ctx, dict):
            continue

        source_type = _safe(ctx.get("source_type"), "").lower()
        retriever = _safe(ctx.get("retriever"), "").lower()
        source = _safe(ctx.get("source") or ctx.get("path"), "").lower()

        is_external = (
            source_type == "external_official"
            or retriever == "official_catalog"
            or "owasp" in source
            or "cwe" in source
            or "mitre" in source
            or "portswigger" in source
            or "mozilla" in source
            or "mdn" in source
        )

        if is_external:
            external_references.append(ctx)
        else:
            internal_contexts.append(ctx)

    return internal_contexts, external_references


def _clean_external_title(source: str, title: str) -> str:
    source = _safe(source, "").strip()
    title = _safe(title, "Official Reference").strip()

    prefixes = [
        "Official Source - ",
        f"{source} - " if source else "",
    ]

    cleaned = title
    for prefix in prefixes:
        if prefix and cleaned.lower().startswith(prefix.lower()):
            cleaned = cleaned[len(prefix):].strip()

    if source and cleaned.lower().startswith(source.lower()):
        cleaned = cleaned[len(source):].strip(" -:")

    return cleaned or title


def _strip_duplicate_urls_from_content(content: str) -> str:
    if not content:
        return ""

    lines = []
    for line in str(content).splitlines():
        normalized = line.strip().lower()

        if normalized.startswith("official url:"):
            continue
        if normalized.startswith("source url:"):
            continue

        lines.append(line)

    cleaned = "\n".join(lines).strip()
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    return cleaned


def _render_internal_contexts(contexts: List[Dict[str, Any]]) -> str:
    if not contexts:
        return "No internal ChromaDB context was retrieved."

    blocks: List[str] = []

    for idx, ctx in enumerate(contexts, start=1):
        title = ctx.get("title") or "Internal Security Guide"
        path = ctx.get("path") or ctx.get("source") or "-"
        score = ctx.get("score")
        retriever = ctx.get("retriever") or "chroma"
        content = ctx.get("content") or ctx.get("text") or ctx.get("chunk") or ""

        block = f"""### 6.{idx}. {title}

{_make_table([
    ("Source", path),
    ("Retriever", retriever),
    ("Vector Score", score),
])}

{FENCE}text
{str(content)[:1200]}
{FENCE}
"""
        blocks.append(block)

    return "\n".join(blocks)


def _render_external_references(references: List[Dict[str, Any]]) -> str:
    if not references:
        return "No external official reference was matched."

    blocks: List[str] = []

    for idx, ref in enumerate(references, start=1):
        source = ref.get("source") or "Official Source"
        title = _clean_external_title(source, ref.get("title") or "Official Reference")
        url = ref.get("url") or ref.get("path") or ref.get("source") or "-"
        score = ref.get("score")
        content = _strip_duplicate_urls_from_content(ref.get("content") or ref.get("text") or ref.get("chunk") or "")

        block = f"""### 7.{idx}. {source} - {title}

{_make_table([
    ("Source", source),
    ("Reference Title", title),
    ("Source URL", url),
    ("Match Score", score),
])}

{FENCE}text
{content[:1000]}
{FENCE}
"""
        blocks.append(block)

    return "\n".join(blocks)


def _get_judgement(finding: Dict[str, Any]) -> Dict[str, Any]:
    return _as_dict(finding.get("agent_judgement") or finding.get("agent_response"))


def _get_url(finding: Dict[str, Any]) -> Any:
    return finding.get("url") or finding.get("target_url")


def _get_finding_id(finding: Dict[str, Any]) -> Any:
    return finding.get("finding_id") or finding.get("id")


def generate_markdown_report(
    finding: Dict[str, Any],
    rag_contexts: List[Dict[str, Any]],
) -> str:
    finding = finding or {}
    evidence = finding.get("evidence", {}) or {}
    judgement = _get_judgement(finding)

    internal_contexts, external_references = _split_contexts(rag_contexts or [])

    generated_at = datetime.utcnow().isoformat() + "Z"

    confidence = judgement.get("confidence") or finding.get("confidence")

    executive_summary = _make_table(
        [
            ("Vulnerability Type", finding.get("vuln_type", "XSS")),
            ("Severity", finding.get("severity", "medium")),
            ("Target URL", _get_url(finding)),
            ("HTTP Method", finding.get("method") or finding.get("http_method")),
            ("Parameter", finding.get("parameter")),
            ("Confidence", confidence),
            ("Next Action", finding.get("next_action")),
        ]
    )

    finding_detail = _make_table(
        [
            ("Finding ID", _get_finding_id(finding)),
            ("Vulnerability Type", finding.get("vuln_type", "XSS")),
            ("Target URL", _get_url(finding)),
            ("HTTP Method", finding.get("method") or finding.get("http_method")),
            ("Affected Parameter", finding.get("parameter")),
            ("Payload", finding.get("payload")),
            ("Severity", finding.get("severity")),
        ]
    )

    reflection_detected = finding.get("reflection_detected")
    reflection_detected = _as_dict(reflection_detected)

    reflection_value = (
        reflection_detected.get("detected")
        if reflection_detected
        else _evidence_get(evidence, "reflection")
    )

    reflected_value = (
        reflection_detected.get("reflected_value")
        if reflection_detected
        else _evidence_get(evidence, "reflected_value", finding.get("payload"))
    )

    response_snippet = (
        finding.get("response_snippet")
        or _evidence_get(evidence, "response_snippet", "")
        or _safe(evidence, "")
    )

    evidence_table = _make_table(
        [
            ("Payload", finding.get("payload")),
            ("Reflection Detected", reflection_value),
            ("Reflected Value", reflected_value),
            ("Verification", reflection_detected.get("verification") if reflection_detected else _evidence_get(evidence, "verification")),
        ]
    )

    judgement_table = _make_table(
        [
            ("Task", judgement.get("task")),
            ("Should Run", judgement.get("should_run")),
            ("Context Known", judgement.get("context_known")),
            ("Confidence", confidence),
            ("Fallback", judgement.get("fallback")),
            ("Reason", judgement.get("reason")),
        ]
    )

    remediation_table = _make_table(
        [
            ("Primary Risk", "User-controlled input is reflected into an HTML response without clear output encoding."),
            ("Impact", "The browser may interpret reflected input as executable HTML or JavaScript."),
            ("Primary Fix", "Apply context-aware output encoding before rendering user-controlled data."),
            ("Defense-in-depth", "Apply Content Security Policy and avoid unsafe DOM APIs."),
        ]
    )

    remediation_controls = """Recommended controls:

1. Encode user-controlled output according to the rendering context.
2. Escape HTML body and HTML attribute values.
3. Avoid direct insertion into JavaScript execution contexts.
4. Prefer safe DOM APIs such as `textContent` instead of `innerHTML`.
5. Validate and normalize input on the server side.
6. Apply Content Security Policy as defense-in-depth.
"""

    internal_section = _render_internal_contexts(internal_contexts)
    external_section = _render_external_references(external_references)

    retest_table = _make_table(
        [
            ("Retest Goal", "Verify that the reflected value is safely encoded or not executed in the browser."),
            ("Payload 1", "<script>alert(1)</script>"),
            ("Payload 2", "\"><img src=x onerror=alert(1)>"),
            ("Expected Result", "Payload is rendered as text, HTML special characters are encoded, and no JavaScript execution occurs."),
        ]
    )

    markdown = f"""# XSSAgent Security Report

Generated at: {generated_at}

## 1. Executive Summary

{executive_summary}

## 2. Finding Detail

{finding_detail}

## 3. Evidence

{evidence_table}

### Response Snippet

{FENCE}html
{_safe(response_snippet)}
{FENCE}

## 4. XSSAgent Judgement

{judgement_table}

## 5. Risk & Remediation

{remediation_table}

{remediation_controls}

## 6. Internal Knowledge Retrieved by ChromaDB

This section contains internal security guidance retrieved from local Markdown documents indexed in ChromaDB.

{internal_section}

## 7. External Official References

This section contains catalog-based official reference matches from OWASP, CWE, MDN, and PortSwigger.

{external_section}

## 8. Retest Recommendation

{retest_table}
"""

    return markdown


def save_report(markdown: str, output_path: str) -> str:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(markdown, encoding="utf-8")
    return str(path)


# Backward-compatible aliases.
def generate_xss_markdown_report(
    finding: Dict[str, Any],
    rag_contexts: List[Dict[str, Any]],
) -> str:
    return generate_markdown_report(finding, rag_contexts)


def make_markdown(
    finding: Dict[str, Any],
    rag_contexts: List[Dict[str, Any]],
) -> str:
    return generate_markdown_report(finding, rag_contexts)


if __name__ == "__main__":
    sample_finding = {
        "finding_id": "xss-demo",
        "vuln_type": "XSS",
        "url": "http://127.0.0.1:5000/search?q=test",
        "method": "GET",
        "parameter": "q",
        "payload": "<script>alert(1)</script>",
        "severity": "medium",
        "next_action": "generate_report",
        "evidence": "Payload reflected in HTTP response; reflected_value=<script>alert(1)</script>",
        "agent_judgement": {
            "task": "selection",
            "should_run": True,
            "context_known": True,
            "confidence": 1.0,
            "fallback": False,
            "reason": "xss-train decision: selection = xss-train",
        },
    }

    sample_contexts = [
        {
            "source_type": "internal_vector",
            "retriever": "chroma",
            "title": "XSS Remediation Guide",
            "path": "docs/security_guides/xss_remediation.md",
            "score": 0.9739,
            "content": "Reflected XSS occurs when user-controlled input is included in an HTTP response without proper output encoding.",
        },
        {
            "source_type": "external_official",
            "retriever": "official_catalog",
            "source": "OWASP",
            "title": "OWASP XSS Prevention Cheat Sheet",
            "url": "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
            "score": 21.0,
            "content": "OWASP recommends context-aware output encoding for XSS prevention.",
        },
    ]

    markdown_report = generate_markdown_report(sample_finding, sample_contexts)
    output = save_report(markdown_report, "reports/generated/test_report.md")
    print(f"saved: {output}")
