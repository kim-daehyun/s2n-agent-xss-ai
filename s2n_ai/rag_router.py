import os
from typing import Any, Dict, List

from s2n_ai.rag_retriever import retrieve_security_context as retrieve_keyword_context
from s2n_ai.vector_rag_retriever import retrieve_vector_security_context


DEFAULT_RAG_BACKEND = os.getenv("RAG_BACKEND", "chroma").lower()


def retrieve_rag_context(
    query: str,
    top_k: int = 3,
    metadata: Dict[str, Any] | None = None,
    backend: str | None = None,
) -> List[Dict[str, Any]]:
    """
    RAG backend router.

    backend:
    - chroma: ChromaDB vector search
    - keyword: local keyword retrieval
    """
    selected_backend = (backend or DEFAULT_RAG_BACKEND).lower()

    if selected_backend == "chroma":
        return retrieve_vector_security_context(
            query=query,
            top_k=top_k,
            metadata=metadata,
        )

    if selected_backend == "keyword":
        return retrieve_keyword_context(
            query=query,
            top_k=top_k,
            metadata=metadata,
        )

    raise ValueError(f"Unsupported RAG backend: {selected_backend}")


if __name__ == "__main__":
    sample_query = "reflected XSS html body output encoding remediation"

    sample_metadata = {
        "vuln_type": "XSS",
        "cwe": "CWE-79",
        "injection_context": "html_body",
        "recommended_docs": ["xss_remediation", "output_encoding"],
    }

    results = retrieve_rag_context(
        query=sample_query,
        top_k=3,
        metadata=sample_metadata,
        backend="chroma",
    )

    for item in results:
        print("-----")
        print("path:", item["path"])
        print("score:", item["score"])
        print("retriever:", item.get("retriever"))
        print("preview:", item["content"][:250].replace("\n", " "))