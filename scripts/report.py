"""
S2N-Agent 벤치마크 마크다운 리포트 생성기.

사용법:
    python3 scripts/report.py                        # eval_results.json → eval_report.md
    python3 scripts/report.py --input my_eval.json   # 커스텀 입력
    python3 scripts/report.py --output report.md     # 커스텀 출력

evaluate.py 실행 후 생성된 eval_results.json을 읽어
plan.md §12 지표 기준으로 마크다운 보고서를 작성합니다.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path


# ── 상수 ─────────────────────────────────────────────────────────────────────

TARGET_PLUGIN_ACCURACY = 0.85
TARGET_FP_REDUCTION = 0.30
TARGET_JSON_PARSE_RATE = 0.95

TASK_LABELS = {
    "a": "Plugin Selection  (Task A)",
    "b": "Payload Planning  (Task B)",
    "c": "False Pos. Filter (Task C)",
    "d": "Multi-step Planner(Task D)",
}


# ── 리포트 생성 ───────────────────────────────────────────────────────────────

def _badge(value: float, target: float) -> str:
    if value >= target:
        return f"**{value:.1%}** ✅"
    elif value >= target * 0.85:
        return f"**{value:.1%}** ⚠️"
    else:
        return f"**{value:.1%}** ❌"


def generate_report(data: dict) -> str:
    model = data.get("model", "unknown")
    adapter = data.get("adapter", "unknown")
    test_file = data.get("test_file", "unknown")
    n_samples = data.get("n_samples", 0)
    overall_acc = data.get("overall_accuracy", 0.0)
    json_rate = data.get("json_parse_rate", 0.0)
    errors = data.get("errors", 0)
    per_task = data.get("per_task", {})
    fp_reduction = data.get("fp_reduction")

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M")

    lines: list[str] = []

    # 헤더
    lines += [
        "# S2N-Agent 벤치마크 리포트",
        "",
        f"> 생성 일시: {generated_at}",
        "",
        "---",
        "",
    ]

    # 메타
    lines += [
        "## 실행 환경",
        "",
        f"| 항목 | 값 |",
        f"|------|----|",
        f"| 모델 | `{model}` |",
        f"| Adapter | `{adapter}` |",
        f"| 테스트 파일 | `{test_file}` |",
        f"| 총 샘플 수 | {n_samples} |",
        f"| 오류 수 | {errors} |",
        "",
    ]

    # 전체 요약
    lines += [
        "## 전체 지표 요약",
        "",
        "| 지표 | 달성값 | 목표 | 판정 |",
        "|------|--------|------|------|",
        f"| 전체 정확도 | {overall_acc:.1%} | 85%+ | {'✅' if overall_acc >= TARGET_PLUGIN_ACCURACY else '❌'} |",
        f"| JSON 파싱 성공률 | {json_rate:.1%} | 95%+ | {'✅' if json_rate >= TARGET_JSON_PARSE_RATE else '❌'} |",
    ]
    if fp_reduction is not None:
        lines.append(
            f"| FP 감소율 (Task C) | {fp_reduction:.1%} | 30%+ | {'✅' if fp_reduction >= TARGET_FP_REDUCTION else '❌'} |"
        )
    lines += ["", "---", ""]

    # 태스크별 상세
    lines += [
        "## 태스크별 상세",
        "",
        "| 태스크 | 샘플 수 | 정확도 | 목표 |",
        "|--------|---------|--------|------|",
    ]
    for task_key, label in TASK_LABELS.items():
        t = per_task.get(task_key, {})
        n = t.get("n", 0)
        acc = t.get("accuracy", 0.0)
        if n == 0:
            lines.append(f"| {label} | — | — | — |")
        else:
            met = "✅" if acc >= TARGET_PLUGIN_ACCURACY else "❌"
            lines.append(f"| {label} | {n} | {_badge(acc, TARGET_PLUGIN_ACCURACY)} | 85%+ {met} |")
    lines += [""]

    # 태스크별 정의
    lines += [
        "---",
        "",
        "## 태스크 정의 (plan.md §5 기준)",
        "",
        "| ID | 태스크 | 입력 | 출력 | 정확도 기준 |",
        "|----|--------|------|------|------------|",
        "| A | Plugin Selection | url, dom, sitemap_summary | plugin, confidence | plugin 일치 |",
        "| B | Payload Planning | plugin, parameter, context | payloads[], bypass_variants[] | payload 1개 이상 일치 |",
        "| C | False Positive Filter | finding, evidence, response_body | verdict, reason | verdict 일치 |",
        "| D | Multi-step Planner | completed[], findings[], sitemap | next_action, reason | next_action 일치 |",
        "",
        "---",
        "",
        "## 배포 가이드",
        "",
        "```bash",
        "# 1. base 모델 배포 (파인튜닝 없이)",
        "bash scripts/deploy_ollama.sh none",
        "",
        "# 2. LoRA adapter 포함 배포",
        "bash scripts/deploy_ollama.sh lora-out/3b",
        "",
        "# 3. 배포 후 검증",
        "python3 scripts/smoke_test.py",
        "",
        "# 4. 전체 평가",
        "python3 scripts/evaluate.py --adapter ollama --model s2n-agent",
        "python3 scripts/report.py",
        "```",
        "",
        "---",
        "",
        "## S2N CLI 통합",
        "",
        "```bash",
        "# assist: AI 권고만 출력, 스캔은 기존 로직",
        "s2n scan -u https://target.com --ai-mode assist",
        "",
        "# smart: AI가 플러그인 자동 선택",
        "s2n scan -u https://target.com --ai-mode smart",
        "",
        "# aggressive: AI 멀티스텝 공격 계획",
        "s2n scan -u https://target.com --ai-mode aggressive --ai-model s2n-agent",
        "```",
        "",
        "---",
        "",
        f"*자동 생성: `python3 scripts/report.py` — {generated_at}*",
    ]

    return "\n".join(lines) + "\n"


# ── 진입점 ────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="S2N-Agent 벤치마크 리포트 생성")
    parser.add_argument("--input", default="eval_results.json", help="evaluate.py 결과 JSON")
    parser.add_argument("--output", default="eval_report.md", help="출력 마크다운 파일")
    args = parser.parse_args()

    in_path = Path(args.input)
    if not in_path.exists():
        print(f"[오류] 입력 파일 없음: {in_path}")
        print("  먼저 평가를 실행하세요: python3 scripts/evaluate.py --adapter ollama")
        raise SystemExit(1)

    with in_path.open(encoding="utf-8") as f:
        data = json.load(f)

    report = generate_report(data)

    out_path = Path(args.output)
    with out_path.open("w", encoding="utf-8") as f:
        f.write(report)

    print(f"리포트 저장: {out_path}")

    # 요약 출력
    overall = data.get("overall_accuracy", 0.0)
    json_rate = data.get("json_parse_rate", 0.0)
    met_acc = "O" if overall >= TARGET_PLUGIN_ACCURACY else "X"
    met_json = "O" if json_rate >= TARGET_JSON_PARSE_RATE else "X"
    print(f"  전체 정확도:    {overall:.1%}  [{met_acc}]  (목표 85%+)")
    print(f"  JSON 파싱 성공: {json_rate:.1%}  [{met_json}]  (목표 95%+)")


if __name__ == "__main__":
    main()
