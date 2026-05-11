from typing import Any, Dict

from s2n_ai.rag_query_builder import (
    build_rag_query_from_finding,
    build_rag_metadata_from_finding,
)
from s2n_ai.rag_router import retrieve_rag_context
from s2n_ai.external_reference_retriever import retrieve_external_references
from s2n_ai.context_merger import merge_contexts, build_report_context


def retrieve_hybrid_context(
    finding: Dict[str, Any],
    top_k_internal: int = 3,
    top_k_external: int = 4,
    internal_backend: str = "chroma",
) -> Dict[str, Any]:
    """
    Hybrid RAG 파이프라인.

    1. Finding v0.2에서 RAG query / metadata 생성
    2. 내부 ChromaDB Vector RAG 검색
    3. 외부 공식 reference catalog 매칭
    4. 내부/외부 근거 병합
    5. report generator가 쓸 context 리스트 생성
    """
    query = build_rag_query_from_finding(finding)
    metadata = build_rag_metadata_from_finding(finding)

    internal_contexts = retrieve_rag_context(
        query=query,
        top_k=top_k_internal,
        metadata=metadata,
        backend=internal_backend,
    )

    external_references = retrieve_external_references(
        query=query,
        top_k=top_k_external,
        finding_metadata=metadata,
    )

    hybrid_context = merge_contexts(
        internal_contexts=internal_contexts,
        external_references=external_references,
        top_k_internal=top_k_internal,
        top_k_external=top_k_external,
    )

    report_contexts = build_report_context(hybrid_context)

    return {
        "query": query,
        "metadata": metadata,
        "internal_contexts": internal_contexts,
        "external_references": external_references,
        "hybrid_context": hybrid_context,
        "report_contexts": report_contexts,
    }


if __name__ == "__main__":
    sample_finding = {
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

    result = retrieve_hybrid_context(sample_finding)

    print("===== Query =====")
    print(result["query"])

    print("\n===== Internal Contexts =====")
    for ctx in result["internal_contexts"]:
        print(ctx.get("title"), ctx.get("score"), ctx.get("retriever"))

    print("\n===== External References =====")
    for ref in result["external_references"]:
        print(ref.get("source"), ref.get("title"), ref.get("score"))

    print("\n===== Report Contexts =====")
    for ctx in result["report_contexts"]:
        print(ctx.get("title"), ctx.get("source_type"), ctx.get("score"))