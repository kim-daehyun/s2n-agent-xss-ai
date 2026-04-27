"""
S2N-Agent 평가 스크립트.

plan.md §12 평가 지표:
  - Plugin 선택 정확도 (Task A): 목표 85%+
  - False Positive 감소율 (Task C): 목표 30%+
  - JSON 파싱 성공률 (전체 태스크): 목표 95%+

사용법:
    # Ollama 모델 평가
    python3 scripts/evaluate.py --adapter ollama --model s2n-agent

    # LoRA adapter 직접 평가 (mlx-lm 필요)
    python3 scripts/evaluate.py --adapter lora-out/3b --model mlx-community/Qwen2.5-Coder-3B-Instruct-4bit

    # test.jsonl 대신 다른 파일 사용
    python3 scripts/evaluate.py --test-file data/test.jsonl --adapter ollama
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any

# ── 평가 지표 상수 ─────────────────────────────────────────────────────────────

TARGET_PLUGIN_ACCURACY = 0.85
TARGET_FP_REDUCTION = 0.30
TARGET_JSON_PARSE_RATE = 0.95

_TASK_PREFIXES = {
    "a": "You are S2N-Agent, a web vulnerability scanner AI.",
    "b": "You are S2N-Agent. Given a vulnerability plugin",
    "c": "You are S2N-Agent. Analyze a vulnerability finding",
    "d": "You are S2N-Agent. Given the completed plugins",
}

_AVAILABLE_PLUGINS = {
    "xss", "sqlinjection", "oscommand", "csrf", "file_upload",
    "brute_force", "soft_brute_force", "jwt", "autobot",
    "path_traversal", "sensitive_files", "react2shell",
}


# ── 클라이언트 팩토리 ─────────────────────────────────────────────────────────

def build_client(adapter: str, model: str, endpoint: str) -> Any:
    if adapter == "ollama":
        sys.path.insert(0, str(Path(__file__).parent.parent))
        from s2nagent.client.ollama import OllamaClient
        return OllamaClient(endpoint=endpoint, model=model)
    else:
        # mlx-lm 로컬 추론
        return _MLXClient(model_path=model, adapter_path=adapter)


class _MLXClient:
    """mlx-lm 로컬 추론 클라이언트 (평가 전용)."""

    def __init__(self, model_path: str, adapter_path: str) -> None:
        try:
            from mlx_lm import load, generate
            self._load = load
            self._gen = generate
        except ImportError:
            print("[오류] mlx-lm 미설치: pip install mlx-lm")
            sys.exit(1)

        print(f"모델 로드 중: {model_path} + adapter={adapter_path}")
        self._model, self._tokenizer = self._load(
            model_path,
            adapter_path=adapter_path if adapter_path != "none" else None,
        )

    def generate(self, prompt: str, *, system: str | None = None) -> dict[str, Any]:
        from mlx_lm.utils import generate as gen

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": prompt})

        formatted = self._tokenizer.apply_chat_template(
            messages, tokenize=False, add_generation_prompt=True
        )
        raw = gen(self._model, self._tokenizer, prompt=formatted, max_tokens=256)
        return json.loads(raw.strip())


# ── 태스크 분류 ───────────────────────────────────────────────────────────────

def classify_task(sample: dict) -> str:
    sys_content = sample["messages"][0]["content"]
    for task, prefix in _TASK_PREFIXES.items():
        if sys_content.startswith(prefix):
            return task
    return "unknown"


# ── 평가 함수 ─────────────────────────────────────────────────────────────────

def evaluate_sample(client: Any, sample: dict) -> dict[str, Any]:
    """단일 샘플 평가. 응답 생성 → JSON 파싱 → 정답 비교."""
    task = classify_task(sample)
    messages = sample["messages"]
    system_msg = messages[0]["content"]
    user_msg = messages[1]["content"]
    expected_raw = messages[2]["content"]

    result = {
        "task": task,
        "json_parsed": False,
        "correct": False,
        "expected": None,
        "predicted": None,
        "error": None,
    }

    try:
        expected = json.loads(expected_raw)
        result["expected"] = expected
    except json.JSONDecodeError:
        result["error"] = "expected JSON parse failed"
        return result

    try:
        predicted = client.generate(user_msg, system=system_msg)
        result["json_parsed"] = True
        result["predicted"] = predicted
    except Exception as e:
        result["error"] = str(e)[:100]
        return result

    # 태스크별 정확도 기준
    if task == "a":
        result["correct"] = predicted.get("plugin") == expected.get("plugin")
    elif task == "b":
        # payload 중 1개 이상 일치
        pred_p = set(predicted.get("payloads", []))
        exp_p = set(expected.get("payloads", []))
        result["correct"] = bool(pred_p & exp_p)
    elif task == "c":
        result["correct"] = predicted.get("verdict") == expected.get("verdict")
    elif task == "d":
        result["correct"] = predicted.get("next_action") == expected.get("next_action")

    return result


def run_evaluation(
    test_file: str,
    adapter: str,
    model: str,
    endpoint: str,
    max_samples: int,
    verbose: bool,
) -> None:
    path = Path(test_file)
    if not path.exists():
        print(f"[오류] test 파일 없음: {path}")
        sys.exit(1)

    with path.open(encoding="utf-8") as f:
        samples = [json.loads(line) for line in f]

    if max_samples > 0:
        samples = samples[:max_samples]

    print(f"\n평가 시작: {len(samples)} samples  ({test_file})")
    print(f"모델: {adapter} / {model}\n")

    client = build_client(adapter, model, endpoint)

    results_by_task: dict[str, list[dict]] = {"a": [], "b": [], "c": [], "d": []}
    errors = 0
    start = time.time()

    for i, sample in enumerate(samples, 1):
        r = evaluate_sample(client, sample)
        task = r["task"]
        if task in results_by_task:
            results_by_task[task].append(r)
        if r["error"]:
            errors += 1
        if verbose or i % 50 == 0:
            status = "O" if r["correct"] else ("E" if r["error"] else "X")
            print(f"  [{i:4d}/{len(samples)}] Task-{task.upper()} {status}", end="", flush=True)
            if i % 10 == 0:
                print()

    elapsed = time.time() - start
    print(f"\n\n{'='*60}")
    print(f"평가 완료  ({elapsed:.1f}초, {elapsed/len(samples)*1000:.0f}ms/샘플)")
    print(f"{'='*60}\n")

    # 태스크별 지표
    total_correct = 0
    total_parsed = 0
    total = 0

    task_labels = {
        "a": "Plugin Selection  (Task A)",
        "b": "Payload Planning  (Task B)",
        "c": "False Pos. Filter (Task C)",
        "d": "Multi-step Planner(Task D)",
    }

    for task, results in results_by_task.items():
        if not results:
            continue
        n = len(results)
        n_correct = sum(1 for r in results if r["correct"])
        n_parsed = sum(1 for r in results if r["json_parsed"])
        acc = n_correct / n
        parse_rate = n_parsed / n

        total_correct += n_correct
        total_parsed += n_parsed
        total += n

        target_met = "O" if acc >= TARGET_PLUGIN_ACCURACY else "X"
        print(f"  {task_labels[task]}")
        print(f"    정확도: {acc:6.1%}  ({n_correct}/{n})  목표 85%+ [{target_met}]")
        print(f"    JSON 파싱 성공률: {parse_rate:6.1%}")
        print()

    # 전체 요약
    if total:
        overall_acc = total_correct / total
        overall_parse = total_parsed / total
        print(f"  {'전체':30s}")
        print(f"    정확도:          {overall_acc:6.1%}  ({total_correct}/{total})")
        print(f"    JSON 파싱 성공률:{overall_parse:6.1%}")
        print(f"    오류:            {errors}")

    # FP 감소율 (Task C 기준)
    c_results = results_by_task.get("c", [])
    if c_results:
        # baseline: 모든 finding을 confirmed로 처리했을 때의 FP 수
        baseline_fp = sum(1 for r in c_results if r["expected"] and r["expected"].get("verdict") == "likely_false_positive")
        # 모델이 correctly 걸러낸 FP
        caught_fp = sum(
            1 for r in c_results
            if r["correct"] and r["expected"] and r["expected"].get("verdict") == "likely_false_positive"
        )
        if baseline_fp > 0:
            fp_reduction = caught_fp / baseline_fp
            target_met = "O" if fp_reduction >= TARGET_FP_REDUCTION else "X"
            print(f"\n  False Positive 감소율: {fp_reduction:.1%}  목표 30%+ [{target_met}]")

    print(f"\n{'='*60}")

    # 결과 저장
    out = Path("eval_results.json")
    summary = {
        "model": model,
        "adapter": adapter,
        "test_file": test_file,
        "n_samples": total,
        "overall_accuracy": total_correct / total if total else 0,
        "json_parse_rate": total_parsed / total if total else 0,
        "errors": errors,
        "per_task": {
            task: {
                "n": len(results),
                "correct": sum(1 for r in results if r["correct"]),
                "accuracy": sum(1 for r in results if r["correct"]) / len(results) if results else 0,
            }
            for task, results in results_by_task.items()
        },
    }
    with out.open("w") as f:
        json.dump(summary, f, indent=2)
    print(f"결과 저장: {out}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="S2N-Agent 평가")
    parser.add_argument("--test-file", default="data/test.jsonl")
    parser.add_argument("--adapter", default="ollama",
                        help="'ollama' 또는 LoRA adapter 디렉토리 경로 (예: lora-out/3b)")
    parser.add_argument("--model", default="s2n-agent",
                        help="Ollama 모델명 또는 HF 모델 경로")
    parser.add_argument("--endpoint", default="http://localhost:11434",
                        help="Ollama 서버 주소")
    parser.add_argument("--max-samples", type=int, default=0,
                        help="평가할 최대 샘플 수 (0=전체)")
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    run_evaluation(
        test_file=args.test_file,
        adapter=args.adapter,
        model=args.model,
        endpoint=args.endpoint,
        max_samples=args.max_samples,
        verbose=args.verbose,
    )
