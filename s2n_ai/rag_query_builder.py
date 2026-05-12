from __future__ import annotations

from typing import Any, Dict, List


def _safe(value: Any, default: str = "unknown") -> str:
    if value is None:
        return default
    if value == "":
        return default
    return str(value)


def _lower(value: Any) -> str:
    return _safe(value, "").lower()


def _as_dict(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    return {}


def _as_list(value: Any) -> List[Any]:
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]


def _normalize_severity(value: Any) -> str:
    raw = _safe(value, "UNKNOWN").strip().upper()

    mapping = {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
        "INFO": "info",
        "INFORMATIONAL": "info",
        "UNKNOWN": "unknown",
    }

    return mapping.get(raw, raw.lower())


def _extract_reflection_flag(finding: Dict[str, Any]) -> bool:
    """
    finding["evidence"]가 str이어도 터지지 않도록 처리한다.
    우선순위:
    1. finding["reflection_detected"]["detected"]
    2. finding["reflected"]
    3. evidence 문자열 내 reflected marker
    """

    reflection = _as_dict(finding.get("reflection_detected"))
    if "detected" in reflection:
        return bool(reflection.get("detected"))

    if "reflected" in finding:
        return bool(finding.get("reflected"))

    evidence_text = _lower(finding.get("evidence"))

    markers = [
        "reflected in http response",
        "payload reflected",
        "payload already present",
        "direct_url_payload_reflected",
        "verification=payload_reflected",
        "verification=direct_url_payload_reflected",
        "without clear output encoding",
        "was reflected",
        "reflected_value=",
    ]

    return any(marker in evidence_text for marker in markers)


def _extract_xss_type(finding: Dict[str, Any]) -> str:
    xss_type = _lower(
        finding.get("xss_type")
        or finding.get("category")
        or finding.get("type")
    )

    text = " ".join(
        [
            xss_type,
            _lower(finding.get("title")),
            _lower(finding.get("description")),
            _lower(finding.get("url") or finding.get("target_url")),
        ]
    )

    if "stored" in text:
        return "stored"
    if "dom" in text:
        return "dom"
    if "reflected" in text or "xss_r" in text:
        return "reflected"

    return "reflected"


def _extract_injection_context(finding: Dict[str, Any]) -> str:
    context = _lower(finding.get("injection_context"))
    if context and context != "unknown":
        return context

    method = _safe(finding.get("method") or finding.get("http_method"), "").upper()
    url = _safe(finding.get("url") or finding.get("target_url"), "")
    evidence = _lower(finding.get("evidence"))

    if method == "GET" and "?" in url:
        return "url_parameter"

    if method == "POST":
        return "form_body"

    if "<pre>" in evidence or "<body" in evidence or "<html" in evidence:
        return "html_body"

    return "unknown"


def _extract_docs(finding: Dict[str, Any]) -> List[str]:
    docs = finding.get("recommended_docs")

    if not docs:
        rag_hints = _as_dict(finding.get("rag_hints"))
        docs = rag_hints.get("recommended_docs")

    docs_list = [str(item) for item in _as_list(docs) if item]

    if docs_list:
        return docs_list

    return [
        "xss_remediation",
        "output_encoding",
        "content_security_policy",
    ]


def _dedupe_keep_order(items: List[str]) -> List[str]:
    seen = set()
    result = []

    for item in items:
        normalized = item.strip()
        if not normalized:
            continue
        key = normalized.lower()
        if key in seen:
            continue
        seen.add(key)
        result.append(normalized)

    return result


def build_rag_query_from_finding(finding: Dict[str, Any]) -> str:
    """
    Build RAG search query from normalized finding.

    중요:
    - finding["evidence"]가 문자열이어도 정상 처리한다.
    - severity는 finding 원본 값을 사용한다.
    - XSS는 CWE-79 / reflected XSS / output encoding 중심으로 검색어를 만든다.
    """

    finding = finding or {}

    vuln_type = _safe(
        finding.get("vuln_type")
        or finding.get("vulnerability_type")
        or "XSS"
    ).upper()

    cwe = _safe(
        finding.get("cwe")
        or finding.get("cve")
        or "CWE-79"
    )

    xss_type = _extract_xss_type(finding)
    injection_context = _extract_injection_context(finding)
    severity = _normalize_severity(finding.get("severity"))
    parameter = _safe(finding.get("parameter"), "unknown")
    payload = _safe(finding.get("payload"), "")

    reflected = _extract_reflection_flag(finding)

    docs = _extract_docs(finding)

    query_parts = [
        vuln_type,
        cwe,
        f"{xss_type} XSS",
        "Cross-Site Scripting",
        "output encoding",
        "context-aware escaping",
        "input validation",
        "HTML encoding",
        "JavaScript encoding",
        "Content Security Policy",
        f"severity {severity}",
        f"parameter {parameter}",
    ]

    if reflected:
        query_parts.append("payload reflected in HTTP response")
        query_parts.append("reflected payload without output encoding")

    if injection_context != "unknown":
        query_parts.append(f"injection context {injection_context}")

    if payload:
        query_parts.append("script payload")
        if "<script" in payload.lower():
            query_parts.append("script tag injection")

    query_parts.extend(docs)

    return " ".join(_dedupe_keep_order(query_parts))


def build_rag_metadata_from_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build structured metadata for hybrid RAG retrieval.
    """

    finding = finding or {}

    vuln_type = _safe(
        finding.get("vuln_type")
        or finding.get("vulnerability_type")
        or "XSS"
    ).upper()

    cwe = _safe(
        finding.get("cwe")
        or finding.get("cve")
        or "CWE-79"
    )

    xss_type = _extract_xss_type(finding)
    injection_context = _extract_injection_context(finding)
    severity = _normalize_severity(finding.get("severity"))
    reflected = _extract_reflection_flag(finding)
    docs = _extract_docs(finding)

    return {
        "vuln_type": vuln_type,
        "cve": cwe,
        "cwe": cwe,
        "owasp_category": _safe(
            finding.get("owasp_category"),
            "Injection / Cross-Site Scripting",
        ),
        "xss_type": xss_type,
        "injection_context": injection_context,
        "severity": severity,
        "parameter": _safe(finding.get("parameter"), "unknown"),
        "payload_type": "script_tag"
        if "<script" in _lower(finding.get("payload"))
        else "unknown",
        "reflection_detected": reflected,
        "recommended_docs": docs,
        "official_references": [
            "OWASP XSS Prevention Cheat Sheet",
            "CWE-79",
            "MDN XSS",
            "PortSwigger Reflected XSS",
        ],
    }


def build_rag_query(normalized_finding: Dict[str, Any]) -> str:
    """
    Backward-compatible alias.
    """
    return build_rag_query_from_finding(normalized_finding)


def build_rag_metadata(normalized_finding: Dict[str, Any]) -> Dict[str, Any]:
    """
    Backward-compatible alias.
    """
    return build_rag_metadata_from_finding(normalized_finding)
