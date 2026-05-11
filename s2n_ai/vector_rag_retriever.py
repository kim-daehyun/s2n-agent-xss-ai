from pathlib import Path
from typing import Any, Dict, List

import chromadb
from chromadb.utils import embedding_functions


CHROMA_DIR = Path("storage/chroma_xss_guides")
COLLECTION_NAME = "xss_security_guides"

EMBEDDING_MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"


def get_chroma_collection():
    client = chromadb.PersistentClient(path=str(CHROMA_DIR))

    embedding_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name=EMBEDDING_MODEL_NAME
    )

    collection = client.get_or_create_collection(
        name=COLLECTION_NAME,
        embedding_function=embedding_fn,
    )

    return collection


def _metadata_boost(
    metadata: Dict[str, Any],
    finding_metadata: Dict[str, Any] | None,
) -> float:
    """
    ChromaDB distance 기반 점수에 Finding metadata 기반 가중치를 추가한다.
    """
    if not finding_metadata:
        return 0.0

    boost = 0.0

    doc_id = str(metadata.get("doc_id", "")).lower()
    path = str(metadata.get("path", "")).lower()
    title = str(metadata.get("title", "")).lower()

    recommended_docs = finding_metadata.get("recommended_docs") or []
    for doc_hint in recommended_docs:
        hint = str(doc_hint).lower()
        if hint and (hint in doc_id or hint in path or hint in title):
            boost += 0.25

    cwe = str(finding_metadata.get("cwe", "")).lower()
    if cwe and cwe in title:
        boost += 0.1

    injection_context = finding_metadata.get("injection_context")
    if injection_context == "html_body" and "xss" in title:
        boost += 0.1

    return boost


def retrieve_vector_security_context(
    query: str,
    top_k: int = 3,
    metadata: Dict[str, Any] | None = None,
) -> List[Dict[str, Any]]:
    """
    ChromaDB 벡터 검색으로 보안 가이드 chunk를 검색한다.

    반환 형식은 기존 report_generator / pdf_generator가 쓰기 쉽게 맞춘다.
    """
    collection = get_chroma_collection()

    result = collection.query(
        query_texts=[query],
        n_results=top_k,
        include=["documents", "metadatas", "distances"],
    )

    documents = result.get("documents", [[]])[0]
    metadatas = result.get("metadatas", [[]])[0]
    distances = result.get("distances", [[]])[0]

    contexts: List[Dict[str, Any]] = []

    for idx, document in enumerate(documents):
        meta = metadatas[idx] if idx < len(metadatas) else {}
        distance = distances[idx] if idx < len(distances) else None

        # Chroma distance는 낮을수록 유사함.
        # 보기 편하게 similarity score 형태로 변환한다.
        if distance is None:
            similarity = 0.0
        else:
            similarity = max(0.0, 1.0 - float(distance))

        boost = _metadata_boost(meta, metadata)
        final_score = round(similarity + boost, 4)

        contexts.append(
            {
                "path": meta.get("path", "unknown"),
                "doc_id": meta.get("doc_id", "unknown"),
                "title": meta.get("title", "unknown"),
                "chunk_id": f"{meta.get('doc_id', 'doc')}#{meta.get('chunk_index', idx)}",
                "score": final_score,
                "distance": distance,
                "retriever": "chroma",
                "embedding_model": EMBEDDING_MODEL_NAME,
                "content": document,
            }
        )

    contexts.sort(key=lambda item: item["score"], reverse=True)

    return contexts[:top_k]


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

    docs = retrieve_vector_security_context(
        query=sample_query,
        top_k=3,
        metadata=sample_metadata,
    )

    for doc in docs:
        print("-----")
        print("path:", doc["path"])
        print("title:", doc["title"])
        print("chunk_id:", doc["chunk_id"])
        print("score:", doc["score"])
        print("distance:", doc["distance"])
        print("retriever:", doc["retriever"])
        print("content preview:", doc["content"][:300].replace("\n", " "))