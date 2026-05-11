from datetime import datetime
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, parse_qs


def _now_id() -> str:
    return f"xss-{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"


def _as_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default

    if isinstance(value, bool):
        return value

    if isinstance(value, str):
        return value.lower() in {"true", "1", "yes", "y"}

    return bool(value)


def _safe_get(data: Dict[str, Any], *keys: str, default: Any = None) -> Any:
    """
    여러 후보 key 중 먼저 존재하는 값을 반환한다.
    DVWA, s2n, custom scanner 등 raw_result 구조가 달라도 어느 정도 흡수하기 위한 함수.
    """
    for key in keys:
        if key in data and data.get(key) is not None:
            return data.get(key)
    return default


def _extract_endpoint(url: str) -> str:
    try:
        parsed = urlparse(url)
        return parsed.path or "/"
    except Exception:
        return "/"


def _infer_parameter_location(url: str, method: str, parameter: Optional[str]) -> str:
    """
    parameter가 query/body/header/cookie 중 어디에 있는지 단순 추론한다.
    """
    if not parameter:
        return "unknown"

    method = (method or "GET").upper()

    try:
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        if parameter in query_params:
            return "query"
    except Exception:
        pass

    if method in {"POST", "PUT", "PATCH"}:
        return "body"

    return "unknown"


def _infer_injection_context(response_snippet: str, reflected_value: str) -> str:
    """
    응답 조각을 바탕으로 XSS injection context를 단순 추론한다.

    중요:
    - payload 자체가 <script>...</script> 형태로 HTML body에 삽입된 경우는 script context가 아니라 html_body로 본다.
      예: <p>You searched for: <script>alert(1)</script></p>
    - script context는 기존 <script> 블록 내부의 문자열 위치에 사용자 입력이 들어간 경우를 의미한다.
      예: <script>var q = 'USER_INPUT';</script>
    """
    snippet = response_snippet or ""
    reflected = reflected_value or ""

    if not snippet:
        return "unknown"

    lower = snippet.lower()
    reflected_lower = reflected.lower()

    # 1. reflected payload가 HTML 태그 형태로 그대로 삽입된 경우
    # 예: <p>You searched for: <script>alert(1)</script></p>
    # 이 경우는 script 태그가 포함되어 있어도 "HTML body에 태그가 삽입된 것"이므로 html_body로 본다.
    if reflected and reflected in snippet:
        stripped = reflected.strip()
        if stripped.startswith("<") and stripped.endswith(">"):
            return "html_body"

    # 2. 기존 script 블록 내부에 사용자 입력이 들어간 경우
    # 예: <script>var q = 'test';</script>
    if "<script" in lower and "</script>" in lower and reflected:
        script_start = lower.find("<script")
        script_end = lower.find("</script>")
        reflected_pos = lower.find(reflected_lower)

        if (
            script_start != -1
            and script_end != -1
            and reflected_pos != -1
            and script_start < reflected_pos < script_end
        ):
            return "script"

    # 3. 이벤트 핸들러 또는 HTML attribute 영역
    if "onerror=" in lower or "onclick=" in lower or "onload=" in lower:
        return "html_attribute"

    # 4. href/src 등 URL attribute 근처
    if "href=" in lower or "src=" in lower:
        return "url_attribute"

    # 5. reflected 값이 응답에 있으면 기본적으로 HTML body 반사로 본다.
    if reflected and reflected in snippet:
        return "html_body"

    return "unknown"


def _detect_encoding(response_snippet: str, reflected_value: str) -> bool:
    """
    payload가 HTML entity로 인코딩되어 보이는지 간단히 판단한다.
    """
    snippet = response_snippet or ""
    reflected = reflected_value or ""

    if not snippet:
        return False

    encoded_markers = ["&lt;", "&gt;", "&quot;", "&#x27;", "&#39;", "&amp;"]

    # reflected_value가 그대로 있으면 인코딩 안 된 것으로 판단
    if reflected and reflected in snippet:
        return False

    # HTML entity marker가 있으면 인코딩된 것으로 판단
    if any(marker in snippet for marker in encoded_markers):
        return True

    return False


def _infer_xss_type(raw_result: Dict[str, Any]) -> str:
    """
    XSS 유형을 추론한다.
    현재는 reflected / stored / dom 정도만 MVP로 구분한다.
    """
    explicit_type = _safe_get(raw_result, "xss_type", "type", "vuln_subtype")
    if explicit_type:
        normalized = str(explicit_type).lower()
        if "stored" in normalized:
            return "stored"
        if "dom" in normalized:
            return "dom"
        if "reflected" in normalized:
            return "reflected"

    if _as_bool(_safe_get(raw_result, "reflection", "reflected", default=False)):
        return "reflected"

    return "unknown"


def _is_execution_confirmed(raw_result: Dict[str, Any]) -> bool:
    """
    실제 브라우저 실행 확인 여부.
    지금은 raw_result에 명시값이 있을 때만 true로 본다.
    """
    return _as_bool(
        _safe_get(
            raw_result,
            "execution_confirmed",
            "browser_execution_confirmed",
            "script_executed",
            default=False,
        )
    )


def _calculate_risk(
    reflection_detected: bool,
    encoded: bool,
    execution_confirmed: bool,
    content_type: str,
    injection_context: str,
    agent_response: Dict[str, Any],
) -> Dict[str, Any]:
    """
    규칙 기반 severity 산정.
    CVSS 정식 계산은 아니고, 리포트 MVP용 risk scoring이다.
    """
    score = 0.0
    rationale: List[str] = []

    fallback = _as_bool(agent_response.get("fallback"), default=False)
    confidence = agent_response.get("confidence", 0.0)

    try:
        confidence_float = float(confidence)
    except Exception:
        confidence_float = 0.0

    if fallback:
        return {
            "severity": "info",
            "score": 1.0,
            "rationale": [
                "Model response used fallback path",
                "Manual review is required before assigning vulnerability severity",
            ],
        }

    if reflection_detected:
        score += 2.0
        rationale.append("User-controlled input is reflected in the response")

    if "text/html" in (content_type or "").lower():
        score += 1.0
        rationale.append("Response content type is HTML")

    if not encoded:
        score += 1.5
        rationale.append("No clear output encoding was detected")

    if injection_context in {"html_body", "html_attribute", "script", "url_attribute"}:
        score += 1.0
        rationale.append(f"Reflected value appears in {injection_context} context")

    if execution_confirmed:
        score += 3.0
        rationale.append("Browser-side script execution was confirmed")

    if confidence_float >= 0.8:
        score += 0.5
        rationale.append("XSSAgent confidence is high")

    if score >= 7.0:
        severity = "high"
    elif score >= 4.0:
        severity = "medium"
    elif score >= 2.0:
        severity = "low"
    else:
        severity = "info"

    return {
        "severity": severity,
        "score": round(score, 1),
        "rationale": rationale,
    }


def _build_rag_hints(
    xss_type: str,
    injection_context: str,
    parameter: Optional[str],
    encoded: bool,
) -> Dict[str, Any]:
    """
    RAG 검색 품질을 높이기 위한 검색 힌트 생성.
    """
    context_term = {
        "html_body": "html body output encoding",
        "html_attribute": "html attribute encoding",
        "script": "javascript string escaping",
        "url_attribute": "url attribute encoding",
        "unknown": "xss output encoding",
    }.get(injection_context, "xss output encoding")

    encoding_term = "encoded output" if encoded else "missing output encoding"

    primary_query = f"{xss_type} XSS {context_term} {encoding_term} remediation"

    if parameter:
        primary_query += f" parameter {parameter}"

    return {
        "primary_query": primary_query,
        "cwe": "CWE-79",
        "owasp_category": "Injection / Cross-Site Scripting",
        "recommended_docs": [
            "xss_remediation",
            "output_encoding",
            "content_security_policy",
        ],
    }


def _build_report_fields(
    parameter: Optional[str],
    xss_type: str,
    injection_context: str,
    encoded: bool,
    risk: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Markdown/PDF 리포트에서 바로 사용할 수 있는 요약 문구 생성.
    """
    param_text = parameter or "the affected parameter"
    title = f"{xss_type.title()} XSS in {param_text}"

    if encoded:
        summary = (
            f"{param_text} appears to be reflected, but output encoding indicators were detected. "
            "Manual review is recommended to confirm exploitability."
        )
        recommended_action = (
            "Verify that context-aware output encoding is consistently applied "
            "and confirm that reflected input cannot execute in the browser."
        )
    else:
        summary = (
            f"User-controlled input from {param_text} is reflected in the response "
            f"within the {injection_context} context without clear output encoding."
        )
        recommended_action = (
            "Apply context-aware output encoding for user-controlled output "
            "and avoid directly rendering untrusted input."
        )

    retest_method = (
        "Submit a harmless validation payload to the affected parameter and verify "
        "that it is safely encoded or not executed in the browser context."
    )

    return {
        "title": title,
        "summary": summary,
        "recommended_action": recommended_action,
        "retest_method": retest_method,
        "severity": risk.get("severity"),
    }


def normalize_xss_finding(
    raw_result: Dict[str, Any],
    agent_response: Dict[str, Any],
) -> Dict[str, Any]:
    """
    XSS raw scanner result와 XSSAgent 응답을 표준 Finding 구조로 정규화한다.

    v0.2 개선사항:
    - target 구조화
    - context 추론
    - evidence 세분화
    - risk/severity 자동 산정
    - rag_hints 생성
    - report 필드 생성
    - 기존 report_generator.py / pdf_generator.py 호환용 legacy 필드 유지
    """

    url = _safe_get(raw_result, "url", "target_url", "request_url", default="")
    method = _safe_get(raw_result, "method", "http_method", default="GET")
    method = str(method).upper()

    parameter = _safe_get(raw_result, "parameter", "param", "name")
    payload = _safe_get(raw_result, "payload", "test_payload", "input_payload")

    response_snippet = _safe_get(
        raw_result,
        "response_snippet",
        "snippet",
        "response_body_snippet",
        "body_snippet",
        default="",
    )

    reflected_value = _safe_get(
        raw_result,
        "reflected_value",
        "reflection_value",
        "matched_value",
        default=payload,
    )

    status_code = _safe_get(raw_result, "status_code", "response_status", default=200)

    content_type = _safe_get(
        raw_result,
        "content_type",
        "response_content_type",
        default="text/html",
    )

    reflection_detected = _as_bool(
        _safe_get(raw_result, "reflection", "reflected", default=False)
    )

    encoded = _detect_encoding(
        response_snippet=response_snippet,
        reflected_value=reflected_value,
    )

    xss_type = _infer_xss_type(raw_result)

    injection_context = _infer_injection_context(
        response_snippet=response_snippet,
        reflected_value=reflected_value,
    )

    execution_confirmed = _is_execution_confirmed(raw_result)

    parameter_location = _infer_parameter_location(
        url=url,
        method=method,
        parameter=parameter,
    )

    risk = _calculate_risk(
        reflection_detected=reflection_detected,
        encoded=encoded,
        execution_confirmed=execution_confirmed,
        content_type=content_type,
        injection_context=injection_context,
        agent_response=agent_response,
    )

    rag_hints = _build_rag_hints(
        xss_type=xss_type,
        injection_context=injection_context,
        parameter=parameter,
        encoded=encoded,
    )

    report_fields = _build_report_fields(
        parameter=parameter,
        xss_type=xss_type,
        injection_context=injection_context,
        encoded=encoded,
        risk=risk,
    )

    finding_id = _safe_get(raw_result, "finding_id", "id", default=_now_id())

    normalized = {
        "finding_id": finding_id,
        "vuln_type": "XSS",

        "target": {
            "url": url,
            "endpoint": _extract_endpoint(url),
            "method": method,
            "parameter": parameter,
            "parameter_location": parameter_location,
        },

        "context": {
            "xss_type": xss_type,
            "injection_context": injection_context,
            "sink": "http_response",
            "encoding_detected": encoded,
            "execution_confirmed": execution_confirmed,
        },

        "evidence": {
            "request": {
                "method": method,
                "url": url,
                "parameter": parameter,
                "payload": payload,
            },
            "response": {
                "status_code": status_code,
                "content_type": content_type,
                "snippet": response_snippet,
            },
            "reflection": {
                "detected": reflection_detected,
                "reflected_value": reflected_value,
                "encoded": encoded,
            },
        },

        "agent_judgement": {
            "task": agent_response.get("task"),
            "should_run": agent_response.get("should_run"),
            "context_known": agent_response.get("context_known"),
            "confidence": agent_response.get("confidence"),
            "reason": agent_response.get("reason"),
            "fallback": agent_response.get("fallback", False),
            "model": {
                "backend": "fastapi",
                "device": "cpu",
                "adapter": "xss-agent-qwen3b-clean-peft",
            },
        },

        "risk": risk,
        "rag_hints": rag_hints,
        "report": report_fields,

        "next_action": _safe_get(
            raw_result,
            "next_action",
            default=agent_response.get("next_action", "generate_report"),
        ),

        # legacy compatibility fields
        # 기존 report_generator.py / pdf_generator.py가 깨지지 않도록 유지
        "url": url,
        "method": method,
        "parameter": parameter,
        "payload": payload,
        "severity": risk.get("severity", raw_result.get("severity", "medium")),
        "legacy_evidence": {
            "reflection": reflection_detected,
            "reflected_value": reflected_value,
            "response_snippet": response_snippet,
        },
    }

    return normalized


def to_legacy_report_finding(normalized: Dict[str, Any]) -> Dict[str, Any]:
    """
    기존 report_generator.py / pdf_generator.py가 기대하는 단순 구조로 변환한다.
    기존 보고서 생성 코드와의 호환용이다.

    콘솔 출력에서는 쓰지 않아도 되지만,
    report_generator.py와 pdf_generator.py가 아직 v0.2 구조를 직접 읽지 못하면 이 함수가 필요하다.
    """

    evidence = normalized.get("evidence", {})
    request = evidence.get("request", {})
    response = evidence.get("response", {})
    reflection = evidence.get("reflection", {})

    return {
        "finding_id": normalized.get("finding_id"),
        "vuln_type": normalized.get("vuln_type", "XSS"),
        "url": normalized.get("target", {}).get("url"),
        "method": normalized.get("target", {}).get("method"),
        "parameter": normalized.get("target", {}).get("parameter"),
        "payload": request.get("payload"),
        "evidence": {
            "reflection": reflection.get("detected"),
            "reflected_value": reflection.get("reflected_value"),
            "response_snippet": response.get("snippet"),
        },
        "agent_judgement": normalized.get("agent_judgement", {}),
        "severity": normalized.get("risk", {}).get("severity"),
        "next_action": normalized.get("next_action", "generate_report"),
    }


if __name__ == "__main__":
    import json

    raw = {
        "url": "http://127.0.0.1:5000/search?q=test",
        "method": "GET",
        "parameter": "q",
        "payload": "<script>alert(1)</script>",
        "reflection": True,
        "reflected_value": "<script>alert(1)</script>",
        "response_snippet": "<p>You searched for: <script>alert(1)</script></p>",
        "status_code": 200,
        "content_type": "text/html",
    }

    agent = {
        "task": "selection",
        "should_run": True,
        "context_known": True,
        "confidence": 1.0,
        "reason": "xss-train decision: selection = xss-train",
        "fallback": False,
    }

    normalized = normalize_xss_finding(raw, agent)

    print("===== Normalized Finding v0.2 =====")
    print(json.dumps(normalized, ensure_ascii=False, indent=2))