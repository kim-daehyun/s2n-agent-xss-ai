from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List





def _safe(value: Any, default: str = "-") -> str:
    if value is None:
        return default
    if value == "":
        return default
    return str(value)


def _first(*values: Any, default: Any = "-") -> Any:
    for value in values:
        if value is not None and value != "":
            return value
    return default


def _normalize_severity(value: Any) -> str:
    raw = _safe(value, "UNKNOWN").strip().upper()

    mapping = {
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
        "INFO": "INFO",
        "INFORMATIONAL": "INFO",
        "UNKNOWN": "UNKNOWN",
    }

    return mapping.get(raw, raw)


def _normalize_confidence(value: Any) -> str:
    raw = _safe(value, "UNKNOWN").strip().upper()

    mapping = {
        "FIRM": "FIRM",
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
        "TENTATIVE": "TENTATIVE",
        "CONFIRMED": "CONFIRMED",
        "UNKNOWN": "UNKNOWN",
    }

    return mapping.get(raw, raw)


def _extract_response_snippet(evidence: str, limit: int = 1600) -> str:
    if not evidence:
        return "-"

    text = str(evidence)

    marker = "snippet="
    if marker in text:
        snippet = text.split(marker, 1)[1].strip()
        return snippet[:limit]

    return text[:limit]


def _extract_reflected_value(evidence: str, payload: str) -> str:
    if payload:
        return payload

    if not evidence:
        return "-"

    patterns = [
        r"reflected_value=([^;]+)",
        r"reflected value=([^;]+)",
        r"payload=([^;]+)",
    ]

    for pattern in patterns:
        match = re.search(pattern, evidence, flags=re.IGNORECASE)
        if match:
            return match.group(1).strip()

    return "-"


def _is_reflected_xss(evidence: str, payload: str) -> bool:
    text = (evidence or "").lower()
    payload_text = (payload or "").lower()

    positive_markers = [
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

    if any(marker in text for marker in positive_markers):
        return True

    if payload_text and payload_text in text:
        return True

    return False


def _infer_xss_type(raw_result: Dict[str, Any], evidence: str) -> str:
    title = _safe(raw_result.get("title"), "").lower()
    description = _safe(raw_result.get("description"), "").lower()
    url = _safe(raw_result.get("url") or raw_result.get("target_url"), "").lower()
    text = f"{title} {description} {url} {evidence}".lower()

    if "stored" in text:
        return "stored"
    if "dom" in text:
        return "dom"
    if "reflected" in text or "xss_r" in text:
        return "reflected"

    return "reflected"


def _infer_injection_context(raw_result: Dict[str, Any], evidence: str) -> str:
    method = _safe(raw_result.get("method") or raw_result.get("http_method"), "").upper()
    parameter = _safe(raw_result.get("parameter"), "")
    url = _safe(raw_result.get("url") or raw_result.get("target_url"), "")
    text = f"{url} {evidence}".lower()

    if method == "GET" and parameter and "?" in url:
        return "url_parameter"

    if method == "POST":
        return "form_body"

    if "<pre>" in text or "<body" in text or "<html" in text:
        return "html_body"

    return "unknown"


def _build_reflection_result(raw_result: Dict[str, Any], payload: str, evidence: str) -> Dict[str, Any]:
    reflected = _is_reflected_xss(evidence, payload)
    reflected_value = _extract_reflected_value(evidence, payload)

    if "direct_url_payload_reflected" in evidence:
        verification = "direct_url_payload_reflected"
    elif "verification=payload_reflected" in evidence:
        verification = "payload_reflected"
    elif reflected:
        verification = "payload_reflected"
    else:
        verification = "not_verified"

    return {
        "detected": reflected,
        "reflected_value": reflected_value,
        "verification": verification,
        "encoded": False if reflected else None,
    }


def _recommended_docs_for_xss() -> List[str]:
    return [
        "xss_remediation",
        "output_encoding",
        "content_security_policy",
    ]


def calculate_risk(finding: Dict[str, Any]) -> Dict[str, Any]:
    severity = _normalize_severity(finding.get("severity"))

    score_map = {
        "CRITICAL": 95,
        "HIGH": 85,
        "MEDIUM": 60,
        "LOW": 35,
        "INFO": 10,
        "UNKNOWN": 50,
    }

    likelihood_map = {
        "CRITICAL": "High",
        "HIGH": "High",
        "MEDIUM": "Medium",
        "LOW": "Low",
        "INFO": "Low",
        "UNKNOWN": "Unknown",
    }

    impact_map = {
        "CRITICAL": "Critical",
        "HIGH": "High",
        "MEDIUM": "Medium",
        "LOW": "Low",
        "INFO": "Informational",
        "UNKNOWN": "Unknown",
    }

    return {
        "severity": severity,
        "risk_score": score_map.get(severity, 50),
        "likelihood": likelihood_map.get(severity, "Unknown"),
        "impact": impact_map.get(severity, "Unknown"),
        "business_impact": (
            "An attacker may execute arbitrary JavaScript in a victim browser, "
            "steal session data, perform actions as the user, or manipulate page content."
            if severity in {"CRITICAL", "HIGH", "MEDIUM"}
            else "Potential client-side security weakness requiring validation."
        ),
    }


def _build_rag_hints(finding: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "vuln_type": "XSS",
        "cwe": "CWE-79",
        "owasp_category": "Injection / Cross-Site Scripting",
        "xss_type": finding.get("xss_type") or "reflected",
        "injection_context": finding.get("injection_context") or "unknown",
        "severity": _normalize_severity(finding.get("severity")),
        "recommended_docs": _recommended_docs_for_xss(),
        "official_references": [
            "OWASP XSS Prevention Cheat Sheet",
            "CWE-79",
            "MDN XSS",
            "PortSwigger Reflected XSS",
        ],
        "query_terms": [
            "XSS",
            "CWE-79",
            "reflected XSS",
            "output encoding",
            "context-aware escaping",
            "Content Security Policy",
        ],
    }


def _build_report_fields(finding: Dict[str, Any]) -> Dict[str, Any]:
    reflection = finding.get("reflection_detected") or {}

    return {
        "title": finding.get("title"),
        "severity": finding.get("severity"),
        "confidence": finding.get("confidence"),
        "target_url": finding.get("target_url"),
        "method": finding.get("method"),
        "parameter": finding.get("parameter"),
        "payload": finding.get("payload"),
        "evidence": finding.get("evidence"),
        "response_snippet": finding.get("response_snippet"),
        "reflection_detected": reflection.get("detected"),
        "reflected_value": reflection.get("reflected_value"),
        "verification": reflection.get("verification"),
        "cwe": finding.get("cwe"),
        "xss_type": finding.get("xss_type"),
        "injection_context": finding.get("injection_context"),
    }


def normalize_xss_finding(
    raw_result: Dict[str, Any],
    agent_response: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Normalize one S2N XSS finding into the internal report/RAG format.

    중요 원칙:
    1. s2n 원본 finding 값을 최우선으로 보존한다.
    2. agent_response는 보조 정보로만 사용한다.
    3. plugin config의 severity_threshold=LOW를 finding severity로 오해하지 않는다.
    4. reflected evidence가 있으면 reflection_detected.detected=True로 보존한다.
    """

    raw_result = raw_result or {}
    agent_response = agent_response or {}

    evidence = _safe(
        _first(
            raw_result.get("evidence"),
            agent_response.get("evidence"),
            default="",
        ),
        "",
    )

    payload = _safe(
        _first(
            raw_result.get("payload"),
            agent_response.get("payload"),
            default="",
        ),
        "",
    )

    parameter = _safe(
        _first(
            raw_result.get("parameter"),
            agent_response.get("parameter"),
            default="-",
        )
    )

    target_url = _safe(
        _first(
            raw_result.get("url"),
            raw_result.get("target_url"),
            raw_result.get("target"),
            agent_response.get("url"),
            agent_response.get("target_url"),
            default="-",
        )
    )

    method = _safe(
        _first(
            raw_result.get("method"),
            raw_result.get("http_method"),
            agent_response.get("method"),
            agent_response.get("http_method"),
            default="GET",
        )
    ).upper()

    severity = _normalize_severity(
        _first(
            raw_result.get("severity"),
            raw_result.get("risk"),
            agent_response.get("severity"),
            default="UNKNOWN",
        )
    )

    confidence = _normalize_confidence(
        _first(
            raw_result.get("confidence"),
            agent_response.get("confidence"),
            default="UNKNOWN",
        )
    )

    finding_id = _safe(
        _first(
            raw_result.get("id"),
            raw_result.get("finding_id"),
            agent_response.get("id"),
            default="xss-unknown",
        )
    )

    title = _safe(
        _first(
            raw_result.get("title"),
            agent_response.get("title"),
            default="Reflected Cross-Site Scripting Detected",
        )
    )

    description = _safe(
        _first(
            raw_result.get("description"),
            agent_response.get("description"),
            default=(
                "User-controlled input was reflected in the HTTP response "
                "without clear output encoding."
            ),
        )
    )

    xss_type = _infer_xss_type(raw_result, evidence)
    injection_context = _infer_injection_context(raw_result, evidence)
    reflection_result = _build_reflection_result(raw_result, payload, evidence)
    response_snippet = _extract_response_snippet(evidence)

    normalized: Dict[str, Any] = {
        "id": finding_id,
        "finding_id": finding_id,

        "title": title,
        "description": description,

        "vuln_type": "XSS",
        "vulnerability_type": "XSS",
        "category": "Reflected XSS" if xss_type == "reflected" else f"{xss_type.title()} XSS",
        "xss_type": xss_type,

        "cwe": "CWE-79",
        "cve": "CWE-79",
        "owasp_category": "Injection / Cross-Site Scripting",

        "severity": severity,
        "confidence": confidence,

        "target_url": target_url,
        "url": target_url,
        "http_method": method,
        "method": method,
        "parameter": parameter,
        "payload": payload or "-",

        "evidence": evidence or "-",
        "response_snippet": response_snippet,

        "reflected": bool(reflection_result.get("detected")),
        "reflected_value": reflection_result.get("reflected_value") or payload or "-",
        "reflection_detected": reflection_result,

        "injection_context": injection_context,

        "source_scanner": "s2n",
        "source_plugin": _safe(raw_result.get("plugin"), "xss"),

        "recommended_docs": _recommended_docs_for_xss(),

        "agent_response": agent_response,
        "raw_result": raw_result,

        "normalized_at": datetime.now(timezone.utc).isoformat(),
    }

    normalized["risk"] = calculate_risk(normalized)
    normalized["rag_hints"] = _build_rag_hints(normalized)
    normalized["report_fields"] = _build_report_fields(normalized)

    return normalized


def _legacy_report_finding(normalized: Dict[str, Any]) -> Dict[str, Any]:
    """
    Backward-compatible shape for older report code.
    기존 코드가 legacy 구조를 기대할 수 있으므로 유지한다.
    """

    normalized = normalized or {}
    reflection = normalized.get("reflection_detected") or {}
    risk = normalized.get("risk") or {}

    return {
        "id": normalized.get("id") or normalized.get("finding_id"),
        "title": normalized.get("title"),
        "severity": normalized.get("severity"),
        "confidence": normalized.get("confidence"),
        "url": normalized.get("url") or normalized.get("target_url"),
        "target_url": normalized.get("target_url") or normalized.get("url"),
        "method": normalized.get("method") or normalized.get("http_method"),
        "parameter": normalized.get("parameter"),
        "payload": normalized.get("payload"),
        "evidence": normalized.get("evidence"),
        "response_snippet": normalized.get("response_snippet"),
        "reflection_detected": reflection,
        "reflected": reflection.get("detected"),
        "reflected_value": reflection.get("reflected_value"),
        "verification": reflection.get("verification"),
        "vuln_type": normalized.get("vuln_type") or "XSS",
        "xss_type": normalized.get("xss_type") or "reflected",
        "cwe": normalized.get("cwe") or "CWE-79",
        "risk_score": risk.get("risk_score"),
        "likelihood": risk.get("likelihood"),
        "impact": risk.get("impact"),
        "recommended_docs": normalized.get("recommended_docs") or _recommended_docs_for_xss(),
    }


def to_legacy_report_finding(normalized: Dict[str, Any]) -> Dict[str, Any]:
    """
    Public compatibility wrapper used by older FastAPI report demo scripts.
    """
    return _legacy_report_finding(normalized)
