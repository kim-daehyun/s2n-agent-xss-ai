"""
S2N-Agent 배포 후 빠른 검증 스크립트.

사용법:
    python3 scripts/smoke_test.py                        # 기본값 (localhost:11434, s2n-agent)
    python3 scripts/smoke_test.py --endpoint http://...  # 커스텀 엔드포인트
    python3 scripts/smoke_test.py --model qwen2.5-coder:7b  # base 모델 검증

종료 코드:
    0 = 전체 통과
    1 = 일부 또는 전체 실패
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

# s2n-agent 패키지 경로 추가
sys.path.insert(0, str(Path(__file__).parent.parent))

# ── 테스트 케이스 ─────────────────────────────────────────────────────────────

_SMOKE_CASES: list[dict[str, Any]] = [
    {
        "name": "Task A — Plugin Selection (XSS 예상)",
        "task": "a",
        "system": "You are S2N-Agent, a web vulnerability scanner AI. Return strict JSON only.",
        "user": json.dumps({
            "url": "/search?q=test",
            "dom": "<input name='q' type='text'>",
            "sitemap_summary": "3 pages, 2 with forms, 0 login forms",
        }),
        "check": lambda r: r.get("plugin") in {
            "xss", "sqlinjection", "autobot",
        },
        "check_desc": "plugin ∈ {xss, sqlinjection, autobot}",
    },
    {
        "name": "Task B — Payload Planning (XSS)",
        "task": "b",
        "system": "You are S2N-Agent. Given a vulnerability plugin and parameter, return payloads as strict JSON.",
        "user": json.dumps({
            "plugin": "xss",
            "parameter": "q",
            "context": "html_body",
        }),
        "check": lambda r: isinstance(r.get("payloads"), list) and len(r["payloads"]) > 0,
        "check_desc": "payloads 리스트 비어 있지 않음",
    },
    {
        "name": "Task C — False Positive Filter",
        "task": "c",
        "system": "You are S2N-Agent. Analyze a vulnerability finding and return verdict as strict JSON.",
        "user": json.dumps({
            "finding": "Possible SQLi detected",
            "evidence": "error near syntax",
            "response_body": "Welcome to our website. Please enjoy your stay.",
        }),
        "check": lambda r: r.get("verdict") in {
            "confirmed", "likely_false_positive",
        },
        "check_desc": "verdict ∈ {confirmed, likely_false_positive}",
    },
    {
        "name": "Task D — Multi-step Planner",
        "task": "d",
        "system": "You are S2N-Agent. Given the completed plugins and findings, plan the next action as strict JSON.",
        "user": json.dumps({
            "completed": ["xss", "csrf"],
            "findings": [{"plugin": "jwt", "severity": "HIGH", "title": "JWT weak secret"}],
            "sitemap": "admin route /admin/panel discovered",
        }),
        "check": lambda r: isinstance(r.get("next_action"), str) and r["next_action"],
        "check_desc": "next_action 문자열 반환",
    },
]


# ── 클라이언트 ────────────────────────────────────────────────────────────────

def _call_ollama(endpoint: str, model: str, system: str, user: str) -> dict[str, Any]:
    import httpx
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ],
        "stream": False,
        "options": {"temperature": 0.1},
    }
    resp = httpx.post(f"{endpoint}/api/chat", json=payload, timeout=60)
    resp.raise_for_status()
    raw = resp.json()["message"]["content"].strip()
    # JSON 블록 추출 (```json ... ``` 감싸기 대응)
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
    return json.loads(raw)


# ── 검증 실행 ─────────────────────────────────────────────────────────────────

def run_smoke(endpoint: str = "http://localhost:11434", model: str = "s2n-agent") -> bool:
    print(f"\nS2N-Agent Smoke Test")
    print(f"  endpoint : {endpoint}")
    print(f"  model    : {model}")
    print(f"{'─'*60}")

    # Ollama 연결 확인
    try:
        import httpx
        r = httpx.get(f"{endpoint}/api/tags", timeout=5)
        r.raise_for_status()
        models = [m["name"] for m in r.json().get("models", [])]
        if not any(model in m for m in models):
            print(f"[경고] 모델 '{model}' 미확인. 등록된 모델: {models}")
    except Exception as e:
        print(f"[오류] Ollama 연결 실패: {e}")
        return False

    passed = 0
    failed = 0

    for case in _SMOKE_CASES:
        name = case["name"]
        t0 = time.time()
        try:
            result = _call_ollama(
                endpoint=endpoint,
                model=model,
                system=case["system"],
                user=case["user"],
            )
            elapsed_ms = int((time.time() - t0) * 1000)
            ok = case["check"](result)
            status = "PASS" if ok else "FAIL"
            symbol = "O" if ok else "X"
            if ok:
                passed += 1
            else:
                failed += 1
            print(f"  [{symbol}] {name}")
            print(f"      검증: {case['check_desc']}")
            print(f"      응답: {json.dumps(result, ensure_ascii=False)[:120]}")
            print(f"      시간: {elapsed_ms}ms")
        except json.JSONDecodeError as e:
            elapsed_ms = int((time.time() - t0) * 1000)
            failed += 1
            print(f"  [X] {name}")
            print(f"      JSON 파싱 실패: {e}")
            print(f"      시간: {elapsed_ms}ms")
        except Exception as e:
            elapsed_ms = int((time.time() - t0) * 1000)
            failed += 1
            print(f"  [X] {name}")
            print(f"      오류: {e}")
            print(f"      시간: {elapsed_ms}ms")
        print()

    total = passed + failed
    print(f"{'─'*60}")
    print(f"결과: {passed}/{total} 통과", end="")
    if failed == 0:
        print("  — 전체 통과!")
    else:
        print(f"  — {failed}개 실패")
    print()

    return failed == 0


# ── 진입점 ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="S2N-Agent smoke test")
    parser.add_argument("--endpoint", default="http://localhost:11434")
    parser.add_argument("--model", default="s2n-agent")
    args = parser.parse_args()

    ok = run_smoke(endpoint=args.endpoint, model=args.model)
    sys.exit(0 if ok else 1)
