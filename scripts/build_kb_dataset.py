"""
KB 데이터 → 학습 샘플 변환 스크립트.

fetch_kb.py 실행 후 data/kb/*.json 을 읽어
각 태스크에 맞는 고품질 JSONL 샘플을 추가 생성합니다.

생성 전략:
  ATT&CK  → Task A (플러그인 선택 근거에 TTP 컨텍스트 추가)
             Task D (TTP 체인 기반 멀티스텝 계획)
  CAPEC   → Task B (실제 공격 패턴 기반 payload 전략)
  WSTG    → Task B (테스트 방법론 기반 payload)
             Task C (WSTG 기대 결과 기반 FP 패턴)
  NVD     → Task C (실제 CVE 설명 기반 confirmed/FP 샘플)

사용법:
    python3 scripts/build_kb_dataset.py
    python3 scripts/build_kb_dataset.py --output data/kb_dataset.jsonl --count 2000
    python3 scripts/build_kb_dataset.py --merge   # 기존 train.jsonl과 병합
"""

from __future__ import annotations

import argparse
import json
import random
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from s2nagent.data.schemas import (
    TASK_A_SYSTEM, TASK_B_SYSTEM, TASK_C_SYSTEM, TASK_D_SYSTEM,
    make_sample,
)

KB_DIR = Path("data/kb")

# ── ATT&CK TID → s2n plugin 매핑 ─────────────────────────────────────────────
_ATTCK_TO_PLUGIN: dict[str, str] = {
    "T1059.007": "xss",
    "T1190":     "sqlinjection",
    "T1185":     "csrf",
    "T1110":     "brute_force",
    "T1528":     "jwt",
    "T1552.001": "sensitive_files",
    "T1505.003": "file_upload",
    "T1083":     "path_traversal",
    "T1059":     "oscommand",
}

# CAPEC ID → plugin 매핑
_CAPEC_TO_PLUGIN: dict[str, str] = {
    "86":  "xss",   "198": "xss",   "588": "xss",
    "7":   "sqlinjection", "66": "sqlinjection",
    "88":  "oscommand",
    "62":  "csrf",
    "76":  "path_traversal", "139": "path_traversal",
    "35":  "file_upload",
    "60":  "jwt",   "196": "jwt",
    "43":  "soft_brute_force",
}

# WSTG key → plugin 매핑
_WSTG_TO_PLUGIN: dict[str, str] = {
    "xss_reflected": "xss",
    "xss_stored":    "xss",
    "sqli":          "sqlinjection",
    "oscommand":     "oscommand",
    "brute_force":   "brute_force",
    "idor":          "path_traversal",
    "session":       "jwt",
}

# CWE → plugin 매핑
_CWE_TO_PLUGIN: dict[str, str] = {
    "CWE-79":  "xss",
    "CWE-89":  "sqlinjection",
    "CWE-78":  "oscommand",
    "CWE-22":  "path_traversal",
    "CWE-434": "file_upload",
    "CWE-352": "csrf",
    "CWE-287": "jwt",
    "CWE-798": "sensitive_files",
}


def _load_kb(name: str) -> list | dict | None:
    path = KB_DIR / name
    if not path.exists():
        print(f"  경고: {path} 없음 — fetch_kb.py 먼저 실행하세요.")
        return None
    with path.open() as f:
        return json.load(f)


# ── ATT&CK 기반 샘플 생성 ────────────────────────────────────────────────────

def _samples_from_attck(techniques: list[dict], n: int) -> list[dict]:
    """ATT&CK 기법 → Task A + Task D 샘플."""
    samples = []
    urls = [
        "/search?q=test", "/api/user?id=1", "/admin/panel",
        "/upload/file", "/login", "/page?file=index.php",
        "/cmd?exec=id", "/api/v1/token", "/download?path=report.pdf",
    ]
    severities = ["HIGH", "CRITICAL", "MEDIUM"]

    for _ in range(n):
        tech = random.choice(techniques)
        tid = tech["id"]
        plugin = _ATTCK_TO_PLUGIN.get(tid, "xss")
        tactics = tech.get("tactics", ["initial-access"])
        desc = tech.get("description", "")
        detection = tech.get("detection", "")

        # ── Task A: ATT&CK 컨텍스트 기반 플러그인 선택 ──────────────────────
        url = random.choice(urls)
        confidence = random.randint(78, 97)

        # description에서 첫 문장을 이유로 사용
        reason_base = desc.split(".")[0].strip()[:120] if desc else f"{tid} technique pattern detected"

        user_a = json.dumps({
            "url": url,
            "dom": f"<input name='q' type='text'>",
            "sitemap_summary": f"ATT&CK {tid} indicators present, tactic: {tactics[0] if tactics else 'unknown'}",
        }, ensure_ascii=False)
        asst_a = json.dumps({
            "plugin": plugin,
            "confidence": confidence,
            "reason": reason_base,
        }, ensure_ascii=False)
        samples.append(make_sample(
            TASK_A_SYSTEM,
            f"Select the best security plugin for this web context:\n{user_a}",
            asst_a,
        ))

        # ── Task D: ATT&CK tactic chain 기반 멀티스텝 계획 ──────────────────
        if len(techniques) >= 2:
            completed = [_ATTCK_TO_PLUGIN.get(t["id"], "xss") for t in random.sample(techniques, 2)]
            completed = list(set(completed))[:2]
            finding_plugin = plugin
            finding_sev = random.choice(severities)

            # 탐지 정보에서 다음 액션 힌트 추출
            next_hints = {
                "initial-access":     ("sqlinjection", "initial access vulnerability found — enumerate further"),
                "execution":          ("oscommand", "code execution found — check for privilege escalation"),
                "persistence":        ("sensitive_files", "persistence mechanism — search for credentials"),
                "credential-access":  ("brute_force", "credential exposure — attempt credential reuse"),
                "collection":         ("path_traversal", "data collection technique — traverse file system"),
                "discovery":          ("autobot", "discovery phase — automate reconnaissance"),
            }
            tactic = tactics[0] if tactics else "initial-access"
            next_action, reason = next_hints.get(tactic, ("path_traversal", "follow-up scanning recommended"))

            user_d = json.dumps({
                "completed_plugins": completed,
                "findings_summary": [{"plugin": finding_plugin, "severity": finding_sev}],
                "sitemap_summary": f"{tid} ({tactic}) technique indicators found",
            }, ensure_ascii=False)
            asst_d = json.dumps({
                "next_action": next_action,
                "reason": reason,
                "priority": "high" if finding_sev in ("CRITICAL", "HIGH") else "medium",
            }, ensure_ascii=False)
            samples.append(make_sample(
                TASK_D_SYSTEM,
                f"Plan the next scan action:\n{user_d}",
                asst_d,
            ))

    return samples


# ── CAPEC 기반 샘플 생성 ──────────────────────────────────────────────────────

def _samples_from_capec(patterns: list[dict], n: int) -> list[dict]:
    """CAPEC 공격 패턴 → Task B (payload 전략) 샘플."""
    samples = []
    contexts = ["html_body", "html_attribute", "js_string", "url_param", "sql_string", "shell_arg"]
    params = ["q", "id", "search", "file", "cmd", "user", "path"]

    for _ in range(n):
        pattern = random.choice(patterns)
        capec_id = pattern["id"]
        plugin = _CAPEC_TO_PLUGIN.get(capec_id, "xss")
        steps = pattern.get("attack_steps", [])
        examples = pattern.get("examples", [])
        name = pattern.get("name", "")

        # 공격 단계에서 payload 추출 (예시 우선, 없으면 단계 설명)
        raw_payloads = examples[:3] if examples else steps[:3]
        payloads = [p[:100] for p in raw_payloads if p]
        if not payloads:
            payloads = [f"CAPEC-{capec_id} test payload"]

        # bypass 변형 생성 (단순 URL 인코딩)
        bypass = [p.replace("<", "%3C").replace(">", "%3E").replace("'", "%27")
                  for p in payloads[:2]]

        context = random.choice(contexts)
        param = random.choice(params)

        user = json.dumps({
            "plugin": plugin,
            "parameter": param,
            "injection_context": context,
            "capec_reference": f"CAPEC-{capec_id}: {name}",
        }, ensure_ascii=False)
        asst = json.dumps({
            "payloads": payloads,
            "bypass_variants": bypass,
            "strategy": f"CAPEC-{capec_id}: {name} — {steps[0][:120] if steps else 'systematic attack'}",
            "context_notes": f"Based on CAPEC-{capec_id} prerequisites: {(pattern.get('prerequisites') or ['none'])[0][:100]}",
        }, ensure_ascii=False)
        samples.append(make_sample(
            TASK_B_SYSTEM,
            f"Generate optimized security test payloads:\n{user}",
            asst,
        ))

    return samples


# ── WSTG 기반 샘플 생성 ───────────────────────────────────────────────────────

def _extract_test_objectives(md_text: str) -> list[str]:
    """WSTG 마크다운에서 테스트 목표 섹션 추출."""
    objectives = []
    in_section = False
    for line in md_text.splitlines():
        if re.match(r"#+\s*(Objectives|Test Objectives|How to Test)", line, re.I):
            in_section = True
        elif re.match(r"^#+\s", line) and in_section:
            in_section = False
        elif in_section and line.strip().startswith("-"):
            obj = line.strip().lstrip("- ").strip()
            if obj and len(obj) > 10:
                objectives.append(obj[:200])
    return objectives[:5]


def _extract_payloads_from_wstg(md_text: str) -> list[str]:
    """WSTG 마크다운 코드블록에서 payload 후보 추출."""
    payloads = []
    in_code = False
    for line in md_text.splitlines():
        if line.strip().startswith("```"):
            in_code = not in_code
        elif in_code:
            stripped = line.strip()
            # 짧고 payload처럼 생긴 것만
            if 5 < len(stripped) < 100 and any(c in stripped for c in "<>'\"%;|/"):
                payloads.append(stripped)
    return payloads[:8]


def _samples_from_wstg(wstg_data: dict[str, str], n: int) -> list[dict]:
    """OWASP WSTG → Task B + Task C 샘플."""
    samples = []
    keys = list(wstg_data.keys())
    if not keys:
        return samples

    for _ in range(n):
        key = random.choice(keys)
        md = wstg_data[key]
        plugin = _WSTG_TO_PLUGIN.get(key, "xss")

        payloads = _extract_payloads_from_wstg(md)
        objectives = _extract_test_objectives(md)

        # ── Task B: WSTG 테스트 케이스 기반 payload ──────────────────────────
        if payloads:
            context_map = {
                "xss_reflected": "html_body",
                "xss_stored":    "html_body",
                "sqli":          "sql_string",
                "oscommand":     "shell_arg",
            }
            context = context_map.get(key, "url_param")
            strategy = objectives[0] if objectives else f"OWASP WSTG {key} test case"

            user_b = json.dumps({
                "plugin": plugin,
                "parameter": "q",
                "injection_context": context,
                "wstg_reference": key,
            }, ensure_ascii=False)
            asst_b = json.dumps({
                "payloads": payloads[:6],
                "bypass_variants": [p.replace(" ", "%20") for p in payloads[:2]],
                "strategy": strategy[:200],
                "context_notes": f"OWASP WSTG methodology: {objectives[1][:100] if len(objectives) > 1 else 'standard test'}",
            }, ensure_ascii=False)
            samples.append(make_sample(
                TASK_B_SYSTEM,
                f"Generate optimized security test payloads:\n{user_b}",
                asst_b,
            ))

        # ── Task C: WSTG 예상 결과 기반 FP 구분 ─────────────────────────────
        # "Expected Results" 섹션에서 confirmed 패턴 추출
        expected_section = ""
        lines = md.splitlines()
        in_exp = False
        for line in lines:
            if re.match(r"#+\s*(Expected Results|Result Expected)", line, re.I):
                in_exp = True
            elif re.match(r"^#+\s", line) and in_exp:
                break
            elif in_exp:
                expected_section += line + " "

        if expected_section.strip() and payloads:
            evidence = payloads[0] if payloads else "test payload"
            user_c = json.dumps({
                "finding": f"Possible {plugin.upper()} vulnerability",
                "evidence": evidence[:100],
                "response_body": expected_section.strip()[:300],
            }, ensure_ascii=False)
            asst_c = json.dumps({
                "verdict": "confirmed",
                "reason": f"OWASP WSTG expected result matched: {expected_section[:80].strip()}",
                "confidence": random.randint(82, 96),
            }, ensure_ascii=False)
            samples.append(make_sample(
                TASK_C_SYSTEM,
                f"Is this a real vulnerability or a false positive?\n{user_c}",
                asst_c,
            ))

    return samples


# ── NVD CVE 기반 샘플 생성 ───────────────────────────────────────────────────

def _samples_from_nvd(cves: list[dict], n: int) -> list[dict]:
    """NVD CVE → Task C (실제 취약점 설명 기반 confirmed/FP 샘플)."""
    samples = []
    if not cves:
        return samples

    # CVSS 8.0+ = confirmed, 4.0 이하 = FP 후보
    high_cves = [c for c in cves if c.get("cvss_score", 0) >= 8.0]
    low_cves  = [c for c in cves if c.get("cvss_score", 0) <= 4.0]

    for _ in range(n):
        is_high = random.random() > 0.4
        pool = high_cves if (is_high and high_cves) else (low_cves or cves)
        cve = random.choice(pool)

        plugin = _CWE_TO_PLUGIN.get(cve.get("cwe", ""), "xss")
        desc = cve.get("description", "")
        score = cve.get("cvss_score", 5.0)
        cve_id = cve.get("id", "CVE-UNKNOWN")

        # description에서 증거 패턴 추출 (첫 문장)
        evidence = desc.split(".")[0][:150] if desc else f"{cve_id} pattern"
        verdict = "confirmed" if score >= 6.0 else "likely_false_positive"
        confidence = min(95, int(50 + score * 5))

        user = json.dumps({
            "finding": f"Possible {plugin.upper()} ({cve_id})",
            "evidence": evidence,
            "response_body": desc[:300],
        }, ensure_ascii=False)
        asst = json.dumps({
            "verdict": verdict,
            "reason": f"CVSS {score} — {'critical severity confirms exploitation' if score >= 7 else 'low severity, insufficient evidence'}",
            "confidence": confidence,
        }, ensure_ascii=False)
        samples.append(make_sample(
            TASK_C_SYSTEM,
            f"Is this a real vulnerability or a false positive?\n{user}",
            asst,
        ))

    return samples


# ── 통합 실행 ────────────────────────────────────────────────────────────────

def build(total: int = 2000, output: str = "data/kb_dataset.jsonl", merge: bool = False) -> None:
    print("KB 데이터 로드 중...")
    attck   = _load_kb("attck_web.json") or []
    capec   = _load_kb("capec_web.json") or []
    wstg    = _load_kb("wstg.json") or {}
    nvd     = _load_kb("nvd_web.json") or []

    if not any([attck, capec, wstg, nvd]):
        print("[오류] KB 데이터 없음. 먼저 실행: python3 scripts/fetch_kb.py")
        sys.exit(1)

    # 소스별 비율 (가용 데이터에 따라 조정)
    n_attck = int(total * 0.30) if attck else 0
    n_capec = int(total * 0.30) if capec else 0
    n_wstg  = int(total * 0.25) if wstg  else 0
    n_nvd   = total - n_attck - n_capec - n_wstg

    print(f"\n샘플 생성 계획:")
    print(f"  ATT&CK ({len(attck)}개 기법) → {n_attck}샘플")
    print(f"  CAPEC  ({len(capec)}개 패턴) → {n_capec}샘플")
    print(f"  WSTG   ({len(wstg)}개 케이스) → {n_wstg}샘플")
    print(f"  NVD    ({len(nvd)}개 CVE)   → {n_nvd}샘플")

    samples: list[dict] = []
    if attck and n_attck > 0:
        samples += _samples_from_attck(attck, n_attck // 2)
    if capec and n_capec > 0:
        samples += _samples_from_capec(capec, n_capec)
    if wstg and n_wstg > 0:
        samples += _samples_from_wstg(wstg, n_wstg)
    if nvd and n_nvd > 0:
        samples += _samples_from_nvd(nvd, n_nvd)

    random.shuffle(samples)
    out_path = Path(output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8") as f:
        for s in samples:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")
    print(f"\nKB 데이터셋 저장: {len(samples)}샘플 → {out_path}")

    if merge:
        base = Path("data/train.jsonl")
        merged_path = Path("data/train_enriched.jsonl")
        base_samples = []
        if base.exists():
            with base.open() as f:
                base_samples = [json.loads(l) for l in f]
        all_samples = base_samples + samples
        random.shuffle(all_samples)
        with merged_path.open("w", encoding="utf-8") as f:
            for s in all_samples:
                f.write(json.dumps(s, ensure_ascii=False) + "\n")
        print(f"병합 완료: {len(base_samples)} + {len(samples)} = {len(all_samples)}샘플 → {merged_path}")
        print("\n재분리 실행:")
        print("  python3 scripts/split_data.py --input data/train_enriched.jsonl")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="KB → 학습 데이터 변환")
    parser.add_argument("--output", default="data/kb_dataset.jsonl")
    parser.add_argument("--count", type=int, default=2000)
    parser.add_argument("--merge", action="store_true", help="기존 train.jsonl과 병합")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    random.seed(args.seed)
    build(args.count, args.output, args.merge)
