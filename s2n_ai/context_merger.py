from typing import Any, Dict, List


def _make_dedupe_key(item: Dict[str, Any]) -> str:
    source_type = item.get("source_type", item.get("retriever", "unknown"))
    title = str(item.get("title", "")).lower().strip()
    path = str(item.get("path", item.get("url", ""))).lower().strip()
    chunk_id = str(item.get("chunk_id", "")).lower().strip()

    return f"{source_type}|{title}|{path}|{chunk_id}"


def _normalize_internal_context(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "source_type": "internal_vector",
        "retriever": item.get("retriever", "chroma"),
        "source": "Internal Security Guide",
        "title": item.get("title", item.get("doc_id", "Internal Guide")),
        "path": item.get("path", "unknown"),
        "url": None,
        "chunk_id": item.get("chunk_id"),
        "score": float(item.get("score", 0.0)),
        "matched_terms": item.get("matched_terms", []),
        "content": item.get("content", ""),
    }


def _normalize_external_context(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "source_type": "external_official",
        "retriever": item.get("retriever", "official_catalog"),
        "source": item.get("source", "External Official Reference"),
        "title": item.get("title", "Official Reference"),
        "path": item.get("path", item.get("url", "")),
        "url": item.get("url"),
        "chunk_id": None,
        "score": float(item.get("score", 0.0)),
        "matched_terms": item.get("matched_terms", []),
        "content": item.get("content", ""),
    }


def merge_contexts(
    internal_contexts: List[Dict[str, Any]],
    external_references: List[Dict[str, Any]],
    top_k_internal: int = 3,
    top_k_external: int = 4,
) -> Dict[str, Any]:
    """
    내부 ChromaDB 검색 결과와 외부 공식 레퍼런스를 병합한다.
    """
    normalized_internal = [
        _normalize_internal_context(item)
        for item in internal_contexts
    ]

    normalized_external = [
        _normalize_external_context(item)
        for item in external_references
    ]

    normalized_internal.sort(key=lambda item: item["score"], reverse=True)
    normalized_external.sort(key=lambda item: item["score"], reverse=True)

    normalized_internal = normalized_internal[:top_k_internal]
    normalized_external = normalized_external[:top_k_external]

    combined = normalized_internal + normalized_external

    deduped: List[Dict[str, Any]] = []
    seen = set()

    for item in combined:
        key = _make_dedupe_key(item)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)

    deduped.sort(
        key=lambda item: (
            1 if item["source_type"] == "external_official" else 0,
            item["score"],
        ),
        reverse=True,
    )

    return {
        "internal_contexts": normalized_internal,
        "external_references": normalized_external,
        "combined_contexts": deduped,
        "summary": {
            "internal_count": len(normalized_internal),
            "external_count": len(normalized_external),
            "combined_count": len(deduped),
        },
    }


def build_report_context(hybrid_context: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    기존 Markdown/PDF generator가 처리할 수 있도록 하나의 context 리스트로 변환한다.
    """
    report_contexts: List[Dict[str, Any]] = []

    for item in hybrid_context.get("combined_contexts", []):
        source_label = (
            f"{item.get('source')} - {item.get('title')}"
            if item.get("source_type") == "external_official"
            else item.get("title")
        )

        content = item.get("content", "")

        if item.get("url"):
            content = f"{content}\n\nSource URL: {item.get('url')}"

        report_contexts.append(
            {
                "path": item.get("path"),
                "title": source_label,
                "score": item.get("score"),
                "source_type": item.get("source_type"),
                "retriever": item.get("retriever"),
                "matched_terms": item.get("matched_terms", []),
                "content": content,
            }
        )

    return report_contexts


if __name__ == "__main__":
    sample_internal = [
        {
            "retriever": "chroma",
            "title": "XSS Remediation Guide",
            "path": "docs/security_guides/xss_remediation.md",
            "chunk_id": "xss_remediation#1",
            "score": 0.97,
            "content": "Internal guide content",
        }
    ]

    sample_external = [
        {
            "source": "OWASP",
            "title": "OWASP XSS Prevention Cheat Sheet",
            "url": "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
            "score": 9.5,
            "content": "Official OWASP guidance",
        }
    ]

    merged = merge_contexts(sample_internal, sample_external)
    print(merged["summary"])

    report_contexts = build_report_context(merged)
    for ctx in report_contexts:
        print(ctx["title"], ctx["score"], ctx["source_type"])