"""
외부 취약점 KB 다운로드 스크립트.

다운로드 대상:
  1. MITRE ATT&CK STIX JSON  (enterprise-attack, 웹 관련 기법 추출)
  2. CAPEC XML               (웹 공격 패턴)
  3. OWASP WSTG Markdown     (테스트 케이스)
  4. NVD CVE JSON            (최근 웹 취약점 샘플)

결과: data/kb/ 디렉토리에 캐시 저장

사용법:
    python3 scripts/fetch_kb.py                    # 전체
    python3 scripts/fetch_kb.py --source attck     # ATT&CK만
    python3 scripts/fetch_kb.py --source capec
    python3 scripts/fetch_kb.py --source wstg
    python3 scripts/fetch_kb.py --source nvd
"""

from __future__ import annotations

import argparse
import gzip
import json
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path

try:
    import requests
except ImportError:
    print("[오류] requests 미설치: pip install requests")
    sys.exit(1)

KB_DIR = Path("data/kb")
KB_DIR.mkdir(parents=True, exist_ok=True)

# ── 소스 URL ─────────────────────────────────────────────────────────────────

ATTCK_URL = (
    "https://raw.githubusercontent.com/mitre/cti/master/"
    "enterprise-attack/enterprise-attack.json"
)
CAPEC_URL = "https://capec.mitre.org/data/xml/capec_latest.xml"
NVD_URL   = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# OWASP WSTG 테스트 케이스 — 웹 취약점과 직접 연관된 파일 목록
WSTG_BASE = (
    "https://raw.githubusercontent.com/OWASP/wstg/master/document/"
    "4-Web_Application_Security_Testing/"
)
WSTG_FILES = {
    "07-Input_Validation_Testing/01-Testing_for_Reflected_Cross_Site_Scripting.md": "xss_reflected",
    "07-Input_Validation_Testing/02-Testing_for_Stored_Cross_Site_Scripting.md":    "xss_stored",
    "07-Input_Validation_Testing/05-Testing_for_SQL_Injection.md":                  "sqli",
    "07-Input_Validation_Testing/12-Testing_for_Command_Injection.md":              "oscommand",
    "07-Input_Validation_Testing/13-Testing_for_Format_String_Injection.md":        "format_string",
    "07-Input_Validation_Testing/15-Testing_for_HTTP_Response_Splitting.md":        "http_split",
    "07-Input_Validation_Testing/07-Testing_for_XML_Injection.md":                  "xml_injection",
    "04-Authentication_Testing/03-Testing_for_Weak_Lock_Out_Mechanism.md":          "brute_force",
    "06-Session_Management_Testing/02-Testing_for_Cookies_Attributes.md":           "session",
    "05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References.md": "idor",
    "10-Business_Logic_Testing/00-Introduction_to_Business_Logic.md":               "business_logic",
}


def _get(url: str, timeout: int = 30, stream: bool = False) -> requests.Response:
    print(f"  다운로드: {url[:80]}...")
    resp = requests.get(url, timeout=timeout, stream=stream)
    resp.raise_for_status()
    return resp


# ── 1. MITRE ATT&CK ─────────────────────────────────────────────────────────

# 웹 취약점 스캐너와 관련된 ATT&CK 기법 ID
_WEB_TECHNIQUE_IDS = {
    "T1059.007",  # JavaScript
    "T1190",      # Exploit Public-Facing Application
    "T1185",      # Man in the Browser / Browser Session Hijacking
    "T1110",      # Brute Force
    "T1528",      # Steal Application Access Token (JWT)
    "T1552.001",  # Credentials In Files
    "T1505.003",  # Web Shell
    "T1083",      # File and Directory Discovery
    "T1046",      # Network Service Scanning
    "T1595.002",  # Vulnerability Scanning
    "T1212",      # Exploitation for Credential Access
}


def fetch_attck() -> list[dict]:
    out_path = KB_DIR / "attck_web.json"
    if out_path.exists():
        print(f"  캐시 사용: {out_path}")
        with out_path.open() as f:
            return json.load(f)

    resp = _get(ATTCK_URL, timeout=120)
    stix = resp.json()

    techniques = []
    for obj in stix.get("objects", []):
        if obj.get("type") != "attack-pattern":
            continue
        ext = obj.get("external_references", [])
        tid = next((r["external_id"] for r in ext if r.get("source_name") == "mitre-attack"), "")
        if not tid:
            continue
        # 웹 관련 기법만 추출 + kill chain이 있는 것
        is_web_relevant = (
            tid in _WEB_TECHNIQUE_IDS
            or any(kc.get("phase_name") in ("initial-access", "execution", "persistence", "credential-access", "collection", "discovery")
                   for kc in obj.get("kill_chain_phases", []))
            and any(kw in obj.get("description", "").lower()
                    for kw in ("web", "http", "sql", "javascript", "browser", "upload", "injection", "authentication"))
        )
        if not is_web_relevant:
            continue

        techniques.append({
            "id": tid,
            "name": obj.get("name", ""),
            "description": obj.get("description", "")[:800],
            "tactics": [kc["phase_name"] for kc in obj.get("kill_chain_phases", [])],
            "platforms": obj.get("x_mitre_platforms", []),
            "detection": obj.get("x_mitre_detection", "")[:400],
            "procedure_examples": [
                r.get("description", "")[:200]
                for r in obj.get("external_references", [])
                if r.get("source_name") not in ("mitre-attack", "capec")
            ][:3],
        })

    with out_path.open("w") as f:
        json.dump(techniques, f, ensure_ascii=False, indent=2)
    print(f"  ATT&CK 기법 저장: {len(techniques)}개 → {out_path}")
    return techniques


# ── 2. CAPEC ─────────────────────────────────────────────────────────────────

# 웹 취약점 관련 CAPEC ID (주요 공격 패턴)
_WEB_CAPEC_IDS = {
    "86",   # XSS via HTTP Query Strings
    "198",  # XSS via HTTP Response Headers
    "588",  # DOM-Based XSS
    "7",    # Blind SQL Injection
    "66",   # SQL Injection
    "88",   # OS Command Injection
    "43",   # Exploiting Multiple Input Fields
    "62",   # Cross-Site Request Forgery
    "60",   # Reusing Session IDs
    "194",  # Fake the Source of Data
    "76",   # Manipulating Web Input to File System Calls (Path Traversal)
    "139",  # Relative Path Traversal
    "35",   # Leverage Executable Code in Non-Executable Files (File Upload)
    "212",  # Functionality Misuse
    "97",   # Cryptanalysis of Cellular Phone Communication (JWT-ish)
    "196",  # Session Credential Falsification through Forging
}


def fetch_capec() -> list[dict]:
    out_path = KB_DIR / "capec_web.json"
    if out_path.exists():
        print(f"  캐시 사용: {out_path}")
        with out_path.open() as f:
            return json.load(f)

    resp = _get(CAPEC_URL, timeout=120)
    root = ET.fromstring(resp.content)
    ns = {"capec": "http://capec.mitre.org/capec-3"}

    patterns = []
    for ap in root.findall(".//capec:Attack_Pattern", ns):
        capec_id = ap.get("ID", "")
        if capec_id not in _WEB_CAPEC_IDS:
            continue

        name = ap.get("Name", "")
        desc_el = ap.find("capec:Description", ns)
        desc = (desc_el.text or "").strip()[:600] if desc_el is not None else ""

        # 실행 흐름 추출
        steps = []
        for phase in ap.findall(".//capec:Attack_Step", ns):
            step_desc = phase.find("capec:Description", ns)
            if step_desc is not None and step_desc.text:
                steps.append(step_desc.text.strip()[:200])

        # 예시 인스턴스 추출
        examples = []
        for ex in ap.findall(".//capec:Example_Instance", ns):
            if ex.text:
                examples.append(ex.text.strip()[:200])

        # 관련 CWE
        cwes = [
            ref.get("CWE_ID", "")
            for ref in ap.findall(".//capec:Related_Weakness", ns)
            if ref.get("CWE_ID")
        ]

        # 전제 조건
        prereqs = []
        for pre in ap.findall(".//capec:Prerequisite", ns):
            if pre.text:
                prereqs.append(pre.text.strip()[:150])

        patterns.append({
            "id": capec_id,
            "name": name,
            "description": desc,
            "attack_steps": steps[:5],
            "examples": examples[:3],
            "cwes": cwes[:5],
            "prerequisites": prereqs[:3],
        })

    with out_path.open("w") as f:
        json.dump(patterns, f, ensure_ascii=False, indent=2)
    print(f"  CAPEC 패턴 저장: {len(patterns)}개 → {out_path}")
    return patterns


# ── 3. OWASP WSTG ────────────────────────────────────────────────────────────

def fetch_wstg() -> dict[str, str]:
    out_path = KB_DIR / "wstg.json"
    if out_path.exists():
        print(f"  캐시 사용: {out_path}")
        with out_path.open() as f:
            return json.load(f)

    result: dict[str, str] = {}
    for path, key in WSTG_FILES.items():
        try:
            resp = _get(f"{WSTG_BASE}{path}", timeout=30)
            result[key] = resp.text[:4000]
            time.sleep(0.3)  # GitHub rate limit 방지
        except Exception as e:
            print(f"    경고: {key} 다운로드 실패 — {e}")

    with out_path.open("w") as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    print(f"  WSTG 테스트 케이스 저장: {len(result)}개 → {out_path}")
    return result


# ── 4. NVD CVE ───────────────────────────────────────────────────────────────

_NVD_CWE_FILTER = {
    "CWE-79",   # XSS
    "CWE-89",   # SQLi
    "CWE-78",   # OS Command Injection
    "CWE-22",   # Path Traversal
    "CWE-434",  # Unrestricted File Upload
    "CWE-352",  # CSRF
    "CWE-287",  # Improper Authentication
    "CWE-798",  # Hardcoded Credentials
    "CWE-362",  # Race Condition
}


def fetch_nvd(max_results: int = 200) -> list[dict]:
    out_path = KB_DIR / "nvd_web.json"
    if out_path.exists():
        print(f"  캐시 사용: {out_path}")
        with out_path.open() as f:
            return json.load(f)

    cves = []
    for cwe in _NVD_CWE_FILTER:
        try:
            params = {
                "cweId": cwe,
                "resultsPerPage": 20,
                "startIndex": 0,
            }
            resp = _get(NVD_URL + "?" + "&".join(f"{k}={v}" for k, v in params.items()), timeout=30)
            data = resp.json()
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                desc_list = cve.get("descriptions", [])
                desc = next((d["value"] for d in desc_list if d.get("lang") == "en"), "")
                metrics = cve.get("metrics", {})
                cvss_list = (
                    metrics.get("cvssMetricV31")
                    or metrics.get("cvssMetricV30")
                    or metrics.get("cvssMetricV2")
                    or []
                )
                score = cvss_list[0]["cvssData"]["baseScore"] if cvss_list else 0.0
                cves.append({
                    "id": cve.get("id", ""),
                    "cwe": cwe,
                    "description": desc[:500],
                    "cvss_score": score,
                    "published": cve.get("published", ""),
                })
            time.sleep(0.6)  # NVD rate limit (5 req/30s)
        except Exception as e:
            print(f"    경고: NVD {cwe} 실패 — {e}")

    cves = cves[:max_results]
    with out_path.open("w") as f:
        json.dump(cves, f, ensure_ascii=False, indent=2)
    print(f"  NVD CVE 저장: {len(cves)}개 → {out_path}")
    return cves


# ── 통합 실행 ────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="취약점 KB 다운로드")
    parser.add_argument(
        "--source", "-s",
        choices=["attck", "capec", "wstg", "nvd", "all"],
        default="all",
    )
    parser.add_argument("--force", action="store_true", help="캐시 무시하고 재다운로드")
    args = parser.parse_args()

    if args.force:
        for f in KB_DIR.glob("*.json"):
            f.unlink()
        print("캐시 삭제 완료.")

    sources = ["attck", "capec", "wstg", "nvd"] if args.source == "all" else [args.source]

    stats: dict[str, int] = {}
    for src in sources:
        print(f"\n[{src.upper()}] 다운로드 시작...")
        try:
            if src == "attck":
                data = fetch_attck()
                stats["attck"] = len(data)
            elif src == "capec":
                data = fetch_capec()
                stats["capec"] = len(data)
            elif src == "wstg":
                data = fetch_wstg()
                stats["wstg"] = len(data)
            elif src == "nvd":
                data = fetch_nvd()
                stats["nvd"] = len(data)
        except Exception as e:
            print(f"  [오류] {src}: {e}")

    print(f"\n완료: {stats}")
    print(f"저장 위치: {KB_DIR.resolve()}/")
    print("\n다음 단계: python3 scripts/build_kb_dataset.py")


if __name__ == "__main__":
    main()
