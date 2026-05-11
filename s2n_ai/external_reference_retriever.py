from typing import Any, Dict, List
import re


OFFICIAL_REFERENCES: List[Dict[str, Any]] = [
    {
        "source": "OWASP",
        "title": "OWASP XSS Prevention Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
        "topics": [
            "xss",
            "cross site scripting",
            "output encoding",
            "html body",
            "html attribute",
            "javascript context",
            "context aware encoding",
            "escaping",
            "remediation",
        ],
        "summary": (
            "OWASP recommends context-aware output encoding and layered defensive controls "
            "to prevent Cross-Site Scripting. Different output contexts such as HTML body, "
            "HTML attributes, JavaScript, CSS, and URL contexts require different encoding rules."
        ),
        "recommended_use": (
            "Use this reference as the primary remediation guideline for XSS output encoding."
        ),
    },
    {
        "source": "OWASP",
        "title": "OWASP DOM based XSS Prevention Cheat Sheet",
        "url": "https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html",
        "topics": [
            "dom xss",
            "dom based xss",
            "javascript",
            "safe dom",
            "innerhtml",
            "textcontent",
            "client side",
        ],
        "summary": (
            "OWASP DOM based XSS guidance focuses on preventing unsafe data flows from "
            "untrusted sources into dangerous DOM sinks."
        ),
        "recommended_use": (
            "Use this reference when the finding involves DOM sinks or client-side JavaScript handling."
        ),
    },
    {
        "source": "CWE",
        "title": "CWE-79: Improper Neutralization of Input During Web Page Generation",
        "url": "https://cwe.mitre.org/data/definitions/79.html",
        "topics": [
            "cwe-79",
            "xss",
            "improper neutralization",
            "web page generation",
            "cross site scripting",
            "classification",
        ],
        "summary": (
            "CWE-79 classifies Cross-Site Scripting as improper neutralization of input "
            "during web page generation."
        ),
        "recommended_use": (
            "Use this reference to classify the weakness and map the finding to CWE-79."
        ),
    },
    {
        "source": "MDN",
        "title": "MDN Content Security Policy Guide",
        "url": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP",
        "topics": [
            "csp",
            "content security policy",
            "xss",
            "defense in depth",
            "script-src",
            "nonce",
            "hash",
        ],
        "summary": (
            "MDN describes Content Security Policy as a defense-in-depth mechanism that can "
            "help reduce the impact of XSS by controlling script execution sources."
        ),
        "recommended_use": (
            "Use this reference as a defense-in-depth recommendation, not as a replacement for output encoding."
        ),
    },
    {
        "source": "MDN",
        "title": "MDN Cross-site scripting XSS",
        "url": "https://developer.mozilla.org/en-US/docs/Web/Security/Attacks/XSS",
        "topics": [
            "xss",
            "cross site scripting",
            "sanitization",
            "output encoding",
            "csp",
            "browser execution",
        ],
        "summary": (
            "MDN explains that XSS can occur when attacker-controlled input is included in a page "
            "without ensuring that it cannot execute as JavaScript."
        ),
        "recommended_use": (
            "Use this reference to explain the browser-side impact and general mitigation direction."
        ),
    },
    {
        "source": "PortSwigger",
        "title": "PortSwigger Web Security Academy: Reflected XSS",
        "url": "https://portswigger.net/web-security/cross-site-scripting/reflected",
        "topics": [
            "reflected xss",
            "xss",
            "http request",
            "immediate response",
            "search parameter",
            "testing",
        ],
        "summary": (
            "PortSwigger describes reflected XSS as occurring when an application receives data "
            "in an HTTP request and includes that data within the immediate response in an unsafe way."
        ),
        "recommended_use": (
            "Use this reference to explain reflected XSS behavior and testing methodology."
        ),
    },
    {
        "source": "PortSwigger",
        "title": "PortSwigger XSS Contexts",
        "url": "https://portswigger.net/web-security/cross-site-scripting/contexts",
        "topics": [
            "xss context",
            "html context",
            "attribute context",
            "javascript context",
            "payload context",
            "escaping",
        ],
        "summary": (
            "PortSwigger explains that XSS exploitability and payload choice depend heavily "
            "on the context where user input is reflected."
        ),
        "recommended_use": (
            "Use this reference when explaining why injection context matters for payload planning and remediation."
        ),
    },
]


def _normalize(text: str) -> str:
    return re.sub(r"\s+", " ", str(text).lower()).strip()


def _tokenize(text: str) -> List[str]:
    normalized = _normalize(text)
    return re.findall(r"[a-zA-Z0-9_\-]+", normalized)


def _score_reference(
    reference: Dict[str, Any],
    query: str,
    finding_metadata: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    finding_metadata = finding_metadata or {}

    query_norm = _normalize(query)
    query_tokens = set(_tokenize(query))

    topics = reference.get("topics", [])
    topic_text = " ".join(topics)
    topic_tokens = set(_tokenize(topic_text))

    title_norm = _normalize(reference.get("title", ""))
    summary_norm = _normalize(reference.get("summary", ""))

    score = 0.0
    matched_terms: List[str] = []

    for token in query_tokens:
        if token in topic_tokens:
            score += 1.5
            matched_terms.append(token)

        if token in title_norm:
            score += 1.0
            matched_terms.append(f"title:{token}")

        if token in summary_norm:
            score += 0.7
            matched_terms.append(f"summary:{token}")

    key_phrases = [
        "reflected xss",
        "cross site scripting",
        "output encoding",
        "html body",
        "html attribute",
        "javascript context",
        "content security policy",
        "cwe-79",
    ]

    for phrase in key_phrases:
        if phrase in query_norm and phrase in topic_text.lower():
            score += 2.5
            matched_terms.append(f"phrase:{phrase}")

        if phrase in query_norm and phrase in title_norm:
            score += 2.0
            matched_terms.append(f"title_phrase:{phrase}")

    cwe = str(finding_metadata.get("cwe", "")).lower()
    if cwe and cwe in _normalize(reference.get("title", "") + " " + topic_text):
        score += 4.0
        matched_terms.append(f"cwe:{cwe}")

    injection_context = finding_metadata.get("injection_context")
    if injection_context == "html_body" and "html body" in topic_text.lower():
        score += 2.0
        matched_terms.append("context:html_body")

    if injection_context == "html_attribute" and "html attribute" in topic_text.lower():
        score += 2.0
        matched_terms.append("context:html_attribute")

    if injection_context == "script" and "javascript" in topic_text.lower():
        score += 2.0
        matched_terms.append("context:javascript")

    xss_type = finding_metadata.get("xss_type")
    if xss_type == "reflected" and "reflected xss" in topic_text.lower():
        score += 2.0
        matched_terms.append("type:reflected_xss")

    source = reference.get("source", "")
    if source in {"OWASP", "CWE", "MDN", "PortSwigger"}:
        score += 0.5
        matched_terms.append(f"official:{source}")

    return {
        "score": round(score, 2),
        "matched_terms": sorted(set(matched_terms)),
    }


def retrieve_external_references(
    query: str,
    top_k: int = 4,
    finding_metadata: Dict[str, Any] | None = None,
) -> List[Dict[str, Any]]:
    """
    OWASP, CWE, MDN, PortSwigger 공식 레퍼런스 카탈로그에서
    Finding과 관련 있는 외부 근거를 매칭한다.

    이 함수는 실시간 웹 검색이 아니라 curated official reference catalog 기반이다.
    """
    results: List[Dict[str, Any]] = []

    for reference in OFFICIAL_REFERENCES:
        scored = _score_reference(
            reference=reference,
            query=query,
            finding_metadata=finding_metadata,
        )

        if scored["score"] <= 0:
            continue

        content = (
            f"{reference['summary']}\n\n"
            f"Recommended use: {reference['recommended_use']}\n\n"
            f"Official URL: {reference['url']}"
        )

        results.append(
            {
                "source_type": "external_official",
                "retriever": "official_catalog",
                "source": reference["source"],
                "title": reference["title"],
                "url": reference["url"],
                "path": reference["url"],
                "score": scored["score"],
                "matched_terms": scored["matched_terms"],
                "content": content,
            }
        )

    results.sort(key=lambda item: item["score"], reverse=True)

    return results[:top_k]


if __name__ == "__main__":
    sample_query = "reflected XSS html body output encoding missing output encoding remediation parameter q"

    sample_metadata = {
        "vuln_type": "XSS",
        "cwe": "CWE-79",
        "owasp_category": "Injection / Cross-Site Scripting",
        "xss_type": "reflected",
        "injection_context": "html_body",
        "severity": "medium",
        "recommended_docs": [
            "xss_remediation",
            "output_encoding",
            "content_security_policy",
        ],
    }

    refs = retrieve_external_references(
        query=sample_query,
        top_k=5,
        finding_metadata=sample_metadata,
    )

    for ref in refs:
        print("-----")
        print("source:", ref["source"])
        print("title:", ref["title"])
        print("score:", ref["score"])
        print("url:", ref["url"])
        print("matched_terms:", ref["matched_terms"])
        print("content:", ref["content"][:250].replace("\n", " "))