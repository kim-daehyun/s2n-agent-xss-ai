from __future__ import annotations

import inspect
import json
import shutil
from pathlib import Path
from typing import Any, Dict, List


PROJECT_ROOT = Path(__file__).resolve().parents[2]
INPUT_JSON = PROJECT_ROOT / "reports/generated/dvwa_s2n_xss_direct_result.json"
NORMALIZED_JSON = PROJECT_ROOT / "reports/generated/dvwa_s2n_xss_normalized.json"
FINAL_PDF = PROJECT_ROOT / "reports/generated/dvwa_s2n_xss_report.pdf"
PORTFOLIO_PDF = PROJECT_ROOT / "reports/generated/dvwa_s2n_xss_portfolio_report.pdf"


def _load_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"Input JSON not found: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def _extract_findings(scan: Dict[str, Any]) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for plugin_result in scan.get("plugin_results", []):
        for finding in plugin_result.get("findings", []):
            if isinstance(finding, dict):
                findings.append(finding)
    return findings


def _call_normalizer(raw_finding: Dict[str, Any]) -> Dict[str, Any]:
    from s2n_ai.finding_normalizer import normalize_xss_finding

    agent_response = {
        "task": "selection",
        "should_run": True,
        "context_known": True,
        "fallback": False,
        "reason": "s2n detected reflected XSS payload in HTTP response.",
        "selected_plugin": "xss",
        "severity": raw_finding.get("severity", "HIGH"),
        "confidence": raw_finding.get("confidence", "FIRM"),
        "payload": raw_finding.get("payload"),
        "parameter": raw_finding.get("parameter"),
        "evidence": raw_finding.get("evidence"),
    }

    sig = inspect.signature(normalize_xss_finding)
    param_names = list(sig.parameters.keys())

    if len(param_names) >= 2:
        return normalize_xss_finding(raw_finding, agent_response)

    return normalize_xss_finding(raw_finding)


def _retrieve_context(normalized: Dict[str, Any]) -> Any:
    try:
        from s2n_ai.hybrid_rag_retriever import retrieve_hybrid_context
        return retrieve_hybrid_context(normalized)
    except Exception as exc:
        print(f"[WARN] real hybrid retriever failed: {type(exc).__name__}: {exc}")
        return [
            {
                "title": "Recommended Fix Summary",
                "source": "docs/security_guides/xss_remediation.md",
                "retriever": "fallback_internal",
                "score": "-",
                "content": "Recommended Fix\n- Apply context-aware output encoding.\n- Escape HTML body output using HTML entity encoding.\n- Escape HTML attribute values.\n- Prefer safe DOM APIs such as textContent instead of innerHTML.\n- Use Content Security Policy as a defense-in-depth control.",
            }
        ]


def main() -> None:
    scan = _load_json(INPUT_JSON)
    findings = _extract_findings(scan)

    if not findings:
        raise RuntimeError(f"No findings found in {INPUT_JSON}")

    representative = findings[0]
    normalized = _call_normalizer(representative)
    normalized["_all_findings"] = findings
    normalized["_scan_summary"] = scan.get("summary", {})
    normalized["_source_s2n_json"] = str(INPUT_JSON)

    NORMALIZED_JSON.write_text(
        json.dumps(normalized, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"[OK] normalized saved: {NORMALIZED_JSON}")
    print(f"[OK] total findings reflected in PDF summary: {len(findings)}")

    rag_contexts = _retrieve_context(normalized)
    print(f"[OK] rag contexts type: {type(rag_contexts).__name__}")

    from s2n_ai.pdf_generator import generate_xss_pdf_report

    pdf_path = generate_xss_pdf_report(
        normalized,
        rag_contexts=rag_contexts,
        all_findings=findings,
        scan_summary=scan.get("summary", {}),
        pdf_path=str(FINAL_PDF),
    )

    shutil.copy2(FINAL_PDF, PORTFOLIO_PDF)
    print(f"[OK] final PDF saved: {pdf_path}")
    print(f"[OK] portfolio copy saved: {PORTFOLIO_PDF}")
    print("[OK] open this file:")
    print(f"open {FINAL_PDF}")


if __name__ == "__main__":
    main()
