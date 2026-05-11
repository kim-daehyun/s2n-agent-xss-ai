from typing import Any, Dict, List


def _safe_get_nested(data: Dict[str, Any], path: List[str], default: Any = None) -> Any:
    current = data

    for key in path:
        if not isinstance(current, dict):
            return default
        current = current.get(key)

    return current if current is not None else default


def _dedupe_keep_order(items: List[str]) -> List[str]:
    seen = set()
    result = []

    for item in items:
        item = str(item).strip()
        if not item:
            continue

        key = item.lower()
        if key in seen:
            continue

        seen.add(key)
        result.append(item)

    return result


def build_rag_query_from_finding(finding: dict) -> str:
    """
    정규화된 Finding에서 RAG 검색용 query를 생성한다.

    우선순위:
    1. v0.2 finding["rag_hints"]["primary_query"] 사용
    2. 없으면 target/context/evidence/risk 기반으로 query 생성
    3. v0.1 legacy 구조도 fallback 지원
    """

    primary_query = _safe_get_nested(finding, ["rag_hints", "primary_query"])
    if primary_query:
        return primary_query

    vuln_type = finding.get("vuln_type", "XSS")

    xss_type = _safe_get_nested(finding, ["context", "xss_type"], "reflected")
    injection_context = _safe_get_nested(
        finding,
        ["context", "injection_context"],
        "unknown",
    )
    encoding_detected = _safe_get_nested(
        finding,
        ["context", "encoding_detected"],
        None,
    )
    execution_confirmed = _safe_get_nested(
        finding,
        ["context", "execution_confirmed"],
        None,
    )

    parameter = _safe_get_nested(finding, ["target", "parameter"])
    parameter_location = _safe_get_nested(finding, ["target", "parameter_location"])
    content_type = _safe_get_nested(finding, ["evidence", "response", "content_type"])
    reflection_detected = _safe_get_nested(
        finding,
        ["evidence", "reflection", "detected"],
        None,
    )

    severity = _safe_get_nested(finding, ["risk", "severity"])
    cwe = _safe_get_nested(finding, ["rag_hints", "cwe"])
    owasp_category = _safe_get_nested(finding, ["rag_hints", "owasp_category"])
    reason = _safe_get_nested(finding, ["agent_judgement", "reason"], "")

    if parameter is None:
        parameter = finding.get("parameter")

    if reflection_detected is None:
        legacy_evidence = finding.get("evidence", {})
        reflection_detected = legacy_evidence.get("reflection")

    context_terms = {
        "html_body": [
            "html body",
            "output encoding",
            "html entity encoding",
            "escaping",
        ],
        "html_attribute": [
            "html attribute",
            "attribute encoding",
            "quote escaping",
            "output encoding",
        ],
        "script": [
            "javascript context",
            "javascript string escaping",
            "script context",
            "output encoding",
        ],
        "url_attribute": [
            "url attribute",
            "url encoding",
            "javascript scheme",
            "href src",
        ],
        "unknown": [
            "xss output encoding",
            "context aware escaping",
        ],
    }.get(injection_context, ["xss output encoding", "context aware escaping"])

    encoding_terms = []
    if encoding_detected is True:
        encoding_terms.extend(["encoded output", "verify exploitability"])
    elif encoding_detected is False:
        encoding_terms.extend(["missing output encoding", "unescaped output"])
    else:
        encoding_terms.extend(["output encoding", "escaping"])

    reflection_terms = []
    if reflection_detected is True:
        reflection_terms.extend(["reflected input", "reflected xss"])
    elif reflection_detected is False:
        reflection_terms.extend(["xss false positive review"])

    execution_terms = []
    if execution_confirmed is True:
        execution_terms.extend(["browser execution confirmed", "high impact xss"])
    elif execution_confirmed is False:
        execution_terms.extend(["execution not confirmed", "manual retest"])

    terms = [
        vuln_type,
        xss_type,
        "cross site scripting",
        "remediation",
        cwe or "CWE-79",
        owasp_category or "",
        severity or "",
        f"parameter {parameter}" if parameter else "",
        f"{parameter_location} parameter" if parameter_location else "",
        content_type or "",
        reason or "",
    ]

    terms.extend(context_terms)
    terms.extend(encoding_terms)
    terms.extend(reflection_terms)
    terms.extend(execution_terms)

    return " ".join(_dedupe_keep_order(terms))


def build_rag_metadata_from_finding(finding: dict) -> dict:
    """
    retriever에서 가중치 계산에 사용할 metadata를 생성한다.
    """
    recommended_docs = _safe_get_nested(
        finding,
        ["rag_hints", "recommended_docs"],
        [],
    )

    if recommended_docs is None:
        recommended_docs = []

    return {
        "vuln_type": finding.get("vuln_type", "XSS"),
        "cwe": _safe_get_nested(finding, ["rag_hints", "cwe"], "CWE-79"),
        "owasp_category": _safe_get_nested(
            finding,
            ["rag_hints", "owasp_category"],
            "Injection / Cross-Site Scripting",
        ),
        "xss_type": _safe_get_nested(finding, ["context", "xss_type"], "unknown"),
        "injection_context": _safe_get_nested(
            finding,
            ["context", "injection_context"],
            "unknown",
        ),
        "severity": _safe_get_nested(finding, ["risk", "severity"], "unknown"),
        "recommended_docs": recommended_docs,
    }


if __name__ == "__main__":
    sample = {
        "vuln_type": "XSS",
        "target": {
            "url": "http://127.0.0.1:5000/search?q=test",
            "endpoint": "/search",
            "method": "GET",
            "parameter": "q",
            "parameter_location": "query",
        },
        "context": {
            "xss_type": "reflected",
            "injection_context": "html_body",
            "sink": "http_response",
            "encoding_detected": False,
            "execution_confirmed": False,
        },
        "evidence": {
            "reflection": {
                "detected": True,
                "reflected_value": "<script>alert(1)</script>",
                "encoded": False,
            },
            "response": {
                "status_code": 200,
                "content_type": "text/html",
                "snippet": "<p>You searched for: <script>alert(1)</script></p>",
            },
        },
        "agent_judgement": {
            "reason": "xss-train decision: selection = xss-train",
        },
        "risk": {
            "severity": "medium",
        },
        "rag_hints": {
            "primary_query": "reflected XSS html body output encoding missing output encoding remediation parameter q",
            "cwe": "CWE-79",
            "owasp_category": "Injection / Cross-Site Scripting",
            "recommended_docs": [
                "xss_remediation",
                "output_encoding",
                "content_security_policy",
            ],
        },
    }

    print("===== RAG Query =====")
    print(build_rag_query_from_finding(sample))

    print("\n===== RAG Metadata =====")
    print(build_rag_metadata_from_finding(sample))