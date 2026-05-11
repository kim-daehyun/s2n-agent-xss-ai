from s2n_ai.fastapi_client import call_xss_agent
from s2n_ai.finding_normalizer import (
    normalize_xss_finding,
    to_legacy_report_finding,
)
from s2n_ai.hybrid_rag_retriever import retrieve_hybrid_context
from s2n_ai.report_generator import generate_markdown_report, save_report
from s2n_ai.pdf_generator import generate_xss_pdf_report


def main():
    request_payload = {
        "task": "selection",
        "url": "http://127.0.0.1:5000/search?q=test",
        "method": "GET",
        "parameters": ["q"],
        "response_sample": "<html><body><p>You searched for: test</p></body></html>",
        "evidence": {
            "reflection": True,
            "reflected_params": ["q"],
        },
    }

    print("[1] Calling FastAPI XSSAgent...")
    agent_response = call_xss_agent(request_payload)

    raw_finding = {
        "url": request_payload["url"],
        "method": request_payload["method"],
        "parameter": "q",
        "payload": "<script>alert(1)</script>",
        "reflection": True,
        "reflected_value": "<script>alert(1)</script>",
        "response_snippet": "<p>You searched for: <script>alert(1)</script></p>",
        "status_code": 200,
        "content_type": "text/html",
    }

    print("[2] Normalizing finding v0.2...")
    normalized_finding = normalize_xss_finding(raw_finding, agent_response)

    print("[3] Retrieving Hybrid RAG context...")
    hybrid_result = retrieve_hybrid_context(
        finding=normalized_finding,
        top_k_internal=3,
        top_k_external=4,
        internal_backend="chroma",
    )

    print("RAG query:", hybrid_result["query"])

    print("\nInternal ChromaDB contexts:")
    for ctx in hybrid_result["internal_contexts"]:
        print(
            f"- {ctx.get('title')} | score={ctx.get('score')} | retriever={ctx.get('retriever')}"
        )

    print("\nExternal official references:")
    for ref in hybrid_result["external_references"]:
        print(
            f"- {ref.get('source')} | {ref.get('title')} | score={ref.get('score')}"
        )

    print("[4] Generating Markdown report with sources...")
    report_finding = to_legacy_report_finding(normalized_finding)
    report_contexts = hybrid_result["report_contexts"]

    markdown = generate_markdown_report(report_finding, report_contexts)
    md_out = save_report(markdown, "reports/generated/fastapi_xss_report.md")
    print(f"✅ Markdown report saved: {md_out}")

    print("[5] Generating PDF report with sources...")
    pdf_out = generate_xss_pdf_report(
        finding=report_finding,
        rag_contexts=report_contexts,
        pdf_path="reports/generated/fastapi_xss_report.pdf",
    )
    print(f"✅ PDF report saved: {pdf_out}")


if __name__ == "__main__":
    main()