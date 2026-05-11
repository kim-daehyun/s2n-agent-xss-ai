from pathlib import Path
from typing import Any, Dict, List
import re


DOC_DIR = Path("docs/security_guides")


def _normalize_text(text: str) -> str:
    return re.sub(r"\s+", " ", text.lower()).strip()


def _tokenize(text: str) -> List[str]:
    text = _normalize_text(text)
    tokens = re.findall(r"[a-zA-Z0-9_\-]+", text)

    stopwords = {
        "the",
        "a",
        "an",
        "and",
        "or",
        "to",
        "of",
        "in",
        "on",
        "for",
        "with",
        "by",
        "is",
        "are",
        "be",
        "this",
        "that",
        "it",
        "as",
        "at",
    }

    return [token for token in tokens if token not in stopwords and len(token) > 1]


def _extract_title(markdown: str, fallback: str) -> str:
    for line in markdown.splitlines():
        line = line.strip()
        if line.startswith("# "):
            return line[2:].strip()
    return fallback


def _split_markdown_into_chunks(
    text: str,
    max_chars: int = 1200,
    overlap: int = 150,
) -> List[str]:
    lines = text.splitlines()
    sections: List[str] = []
    current: List[str] = []

    for line in lines:
        if line.startswith("#") and current:
            sections.append("\n".join(current).strip())
            current = [line]
        else:
            current.append(line)

    if current:
        sections.append("\n".join(current).strip())

    chunks: List[str] = []

    for section in sections:
        if len(section) <= max_chars:
            if section.strip():
                chunks.append(section.strip())
            continue

        start = 0
        while start < len(section):
            end = start + max_chars
            chunk = section[start:end].strip()
            if chunk:
                chunks.append(chunk)
            if end >= len(section):
                break
            start = max(0, end - overlap)

    return chunks


def _load_document_chunks(doc_dir: Path = DOC_DIR) -> List[Dict[str, Any]]:
    chunks: List[Dict[str, Any]] = []

    for path in sorted(doc_dir.glob("*.md")):
        text = path.read_text(encoding="utf-8")
        title = _extract_title(text, fallback=path.stem)

        for idx, chunk_text in enumerate(_split_markdown_into_chunks(text)):
            chunks.append(
                {
                    "path": str(path),
                    "doc_id": path.stem,
                    "title": title,
                    "chunk_id": f"{path.stem}#{idx}",
                    "content": chunk_text,
                }
            )

    return chunks


def _score_chunk(
    query: str,
    chunk: Dict[str, Any],
    metadata: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    metadata = metadata or {}

    query_norm = _normalize_text(query)
    content_norm = _normalize_text(chunk.get("content", ""))
    title_norm = _normalize_text(chunk.get("title", ""))
    path_norm = _normalize_text(chunk.get("path", ""))
    doc_id_norm = _normalize_text(chunk.get("doc_id", ""))

    query_tokens = _tokenize(query)
    content_tokens = set(_tokenize(chunk.get("content", "")))
    title_tokens = set(_tokenize(chunk.get("title", "")))

    score = 0.0
    matched_terms: List[str] = []

    for token in query_tokens:
        if token in content_tokens:
            score += 1.0
            matched_terms.append(token)

        if token in title_tokens:
            score += 1.5
            matched_terms.append(f"title:{token}")

    key_phrases = [
        "reflected xss",
        "cross site scripting",
        "output encoding",
        "html body",
        "html attribute",
        "javascript context",
        "content security policy",
        "safe dom",
        "input validation",
        "cwe-79",
    ]

    for phrase in key_phrases:
        if phrase in query_norm and phrase in content_norm:
            score += 3.0
            matched_terms.append(f"phrase:{phrase}")

    cwe = str(metadata.get("cwe", "")).lower()
    if cwe and cwe in content_norm:
        score += 3.0
        matched_terms.append(f"cwe:{cwe}")

    recommended_docs = metadata.get("recommended_docs") or []
    for doc_hint in recommended_docs:
        hint = _normalize_text(str(doc_hint))
        if hint and (hint in doc_id_norm or hint in path_norm):
            score += 4.0
            matched_terms.append(f"recommended_doc:{hint}")

    injection_context = metadata.get("injection_context")
    context_boost_terms = {
        "html_body": ["html body", "html entity", "output encoding"],
        "html_attribute": ["attribute encoding", "html attribute", "quotes"],
        "script": ["javascript", "script context", "string escaping"],
        "url_attribute": ["url encoding", "href", "src", "url attribute"],
    }.get(injection_context, [])

    for term in context_boost_terms:
        if term in content_norm:
            score += 1.5
            matched_terms.append(f"context:{term}")

    vuln_type = str(metadata.get("vuln_type", "")).lower()
    if vuln_type and vuln_type in content_norm:
        score += 1.5
        matched_terms.append(f"vuln:{vuln_type}")

    return {
        "score": round(score, 2),
        "matched_terms": sorted(set(matched_terms)),
    }


def retrieve_security_context(
    query: str,
    top_k: int = 3,
    metadata: Dict[str, Any] | None = None,
    doc_dir: Path = DOC_DIR,
) -> List[Dict[str, Any]]:
    chunks = _load_document_chunks(doc_dir=doc_dir)
    results: List[Dict[str, Any]] = []

    for chunk in chunks:
        scored = _score_chunk(query, chunk, metadata=metadata)

        if scored["score"] <= 0:
            continue

        results.append(
            {
                "path": chunk["path"],
                "doc_id": chunk["doc_id"],
                "title": chunk["title"],
                "chunk_id": chunk["chunk_id"],
                "score": scored["score"],
                "matched_terms": scored["matched_terms"],
                "retriever": "keyword",
                "content": chunk["content"],
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

    docs = retrieve_security_context(
        query=sample_query,
        top_k=3,
        metadata=sample_metadata,
    )

    for doc in docs:
        print("-----")
        print("path:", doc["path"])
        print("chunk_id:", doc["chunk_id"])
        print("score:", doc["score"])
        print("matched_terms:", doc["matched_terms"])
        print("retriever:", doc["retriever"])
        print("content preview:", doc["content"][:300].replace("\n", " "))