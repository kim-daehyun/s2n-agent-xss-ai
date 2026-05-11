from pathlib import Path
from typing import Any, Dict, List
import hashlib
import json
import re

import chromadb
from chromadb.utils import embedding_functions


DOC_DIR = Path("docs/security_guides")
CHROMA_DIR = Path("storage/chroma_xss_guides")
COLLECTION_NAME = "xss_security_guides"

EMBEDDING_MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"


def normalize_whitespace(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def extract_title(markdown: str, fallback: str) -> str:
    for line in markdown.splitlines():
        line = line.strip()
        if line.startswith("# "):
            return line[2:].strip()
    return fallback


def split_markdown_into_chunks(
    text: str,
    max_chars: int = 1200,
    overlap: int = 150,
) -> List[str]:
    """
    Markdown 문서를 heading 기준으로 나눈 뒤, 너무 긴 섹션은 길이 기준으로 다시 나눈다.
    """
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
        section = section.strip()
        if not section:
            continue

        if len(section) <= max_chars:
            chunks.append(section)
            continue

        start = 0
        while start < len(section):
            end = min(start + max_chars, len(section))
            chunk = section[start:end].strip()
            if chunk:
                chunks.append(chunk)

            if end >= len(section):
                break

            start = max(0, end - overlap)

    return chunks


def stable_chunk_id(path: Path, chunk_index: int, content: str) -> str:
    digest = hashlib.sha1(content.encode("utf-8")).hexdigest()[:12]
    return f"{path.stem}-{chunk_index}-{digest}"


def load_security_docs(doc_dir: Path = DOC_DIR) -> List[Dict[str, Any]]:
    docs: List[Dict[str, Any]] = []

    for path in sorted(doc_dir.glob("*.md")):
        markdown = path.read_text(encoding="utf-8")
        title = extract_title(markdown, fallback=path.stem)
        chunks = split_markdown_into_chunks(markdown)

        for idx, chunk in enumerate(chunks):
            chunk_id = stable_chunk_id(path, idx, chunk)

            docs.append(
                {
                    "id": chunk_id,
                    "content": chunk,
                    "metadata": {
                        "path": str(path),
                        "doc_id": path.stem,
                        "title": title,
                        "chunk_index": idx,
                        "source_type": "security_guide",
                    },
                }
            )

    return docs


def get_chroma_collection(reset: bool = False):
    CHROMA_DIR.mkdir(parents=True, exist_ok=True)

    client = chromadb.PersistentClient(path=str(CHROMA_DIR))

    embedding_fn = embedding_functions.SentenceTransformerEmbeddingFunction(
        model_name=EMBEDDING_MODEL_NAME
    )

    if reset:
        existing = [c.name for c in client.list_collections()]
        if COLLECTION_NAME in existing:
            client.delete_collection(COLLECTION_NAME)

    collection = client.get_or_create_collection(
        name=COLLECTION_NAME,
        embedding_function=embedding_fn,
        metadata={
            "description": "XSS security guide chunks for RAG-based reporting",
            "embedding_model": EMBEDDING_MODEL_NAME,
        },
    )

    return collection


def build_vector_index(reset: bool = True) -> Dict[str, Any]:
    docs = load_security_docs(DOC_DIR)

    if not docs:
        raise RuntimeError(f"No markdown documents found in {DOC_DIR}")

    collection = get_chroma_collection(reset=reset)

    ids = [doc["id"] for doc in docs]
    documents = [doc["content"] for doc in docs]
    metadatas = [doc["metadata"] for doc in docs]

    collection.add(
        ids=ids,
        documents=documents,
        metadatas=metadatas,
    )

    summary = {
        "collection": COLLECTION_NAME,
        "chroma_dir": str(CHROMA_DIR),
        "embedding_model": EMBEDDING_MODEL_NAME,
        "document_count": len(docs),
        "source_dir": str(DOC_DIR),
    }

    return summary


if __name__ == "__main__":
    summary = build_vector_index(reset=True)
    print(json.dumps(summary, ensure_ascii=False, indent=2))