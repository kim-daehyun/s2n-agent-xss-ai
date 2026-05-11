from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel


def load_jsonl(path: str) -> List[Dict[str, Any]]:
    rows = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def write_json(path: str, obj: Any) -> None:
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)


def extract_expected(record: Dict[str, Any]) -> Dict[str, Any]:
    if "expected_json" in record and isinstance(record["expected_json"], dict):
        return record["expected_json"]

    for m in record.get("messages", []):
        if m.get("role") == "assistant":
            content = m.get("content", "")
            return parse_json(content) or {}
    return {}


def get_prompt_messages(record: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    train/test jsonl의 messages에서 assistant 정답을 제거하고
    system + user만 모델 입력으로 사용한다.
    """
    messages = []
    for m in record.get("messages", []):
        if m.get("role") in ("system", "user"):
            messages.append({
                "role": m["role"],
                "content": m.get("content", "")
            })
    return messages


def parse_json(text: str) -> Optional[Dict[str, Any]]:
    """
    모델 출력에서 JSON object만 추출.
    ```json ... ``` 또는 앞뒤 설명이 섞여도 최대한 파싱.
    """
    if not text:
        return None

    text = text.strip()

    # markdown fence 제거
    text = re.sub(r"^```(?:json)?", "", text.strip(), flags=re.IGNORECASE).strip()
    text = re.sub(r"```$", "", text.strip()).strip()

    # 바로 파싱
    try:
        obj = json.loads(text)
        if isinstance(obj, dict):
            return obj
    except Exception:
        pass

    # 첫 { 부터 마지막 } 까지 추출
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        snippet = text[start:end + 1]
        try:
            obj = json.loads(snippet)
            if isinstance(obj, dict):
                return obj
        except Exception:
            return None

    return None


def normalize_actual(task: str, actual: Dict[str, Any]) -> Dict[str, Any]:
    """
    혹시 모델이 selection: {...} 처럼 감싸서 출력한 경우를 대비.
    """
    if task in actual and isinstance(actual[task], dict):
        return actual[task]

    # 발표용 JSON처럼 payload_planning 대신 attack_plan 등으로 나온 경우 최소 보정
    aliases = {
        "payload_planning": ["attack_plan", "payload_plan"],
        "false_positive": ["false_positive_check", "fp_check"],
        "next_action": ["next"],
        "selection": ["task_selection", "plugin_selection"],
    }
    for alias in aliases.get(task, []):
        if alias in actual and isinstance(actual[alias], dict):
            return actual[alias]

    return actual


def get_injection_context(actual: Dict[str, Any]) -> Any:
    """
    actual["injection_context"] 또는 actual["context"]["injection_context"] 모두 허용.
    """
    if "injection_context" in actual:
        return actual.get("injection_context")
    ctx = actual.get("context")
    if isinstance(ctx, dict):
        return ctx.get("injection_context")
    return None


def check_record(task: str, expected: Dict[str, Any], actual: Dict[str, Any]) -> Dict[str, bool]:
    if task == "selection":
        expected_should = expected.get("should_run")
        actual_should = actual.get("should_run")
        ctx = get_injection_context(actual)

        return {
            "should_run": actual_should == expected_should,
            "plugin": actual.get("plugin") == expected.get("plugin", "xss"),
            "context_known": ctx not in (None, "", "unknown"),
        }

    if task == "payload_planning":
        payloads = actual.get("payloads")
        bypass = actual.get("bypass_variants")

        schema_valid = (
            isinstance(actual, dict)
            and isinstance(payloads, list)
            and "strategy" in actual
            and "context_notes" in actual
            and "bypass_variants" in actual
        )

        return {
            "schema_valid": schema_valid,
            "has_payloads": bool(payloads),
            "has_strategy": bool(actual.get("strategy")),
            "has_context_notes": bool(actual.get("context_notes")),
        }

    if task == "false_positive":
        return {
            "verdict": actual.get("verdict") == expected.get("verdict"),
            "confidence_present": isinstance(actual.get("confidence"), int),
            "reason_present": bool(actual.get("reason")),
        }

    if task == "next_action":
        return {
            "next_action": actual.get("next_action") == expected.get("next_action"),
            "priority": actual.get("priority") == expected.get("priority"),
            "reason_present": bool(actual.get("reason")),
        }

    return {"unknown_task": False}


def generate_one(tokenizer, model, messages: List[Dict[str, str]], max_new_tokens: int) -> str:
    prompt = tokenizer.apply_chat_template(
        messages,
        tokenize=False,
        add_generation_prompt=True
    )

    inputs = tokenizer(prompt, return_tensors="pt")
    inputs = {k: v.to(model.device) for k, v in inputs.items()}

    with torch.no_grad():
        out = model.generate(
            **inputs,
            max_new_tokens=max_new_tokens,
            do_sample=False,
            temperature=None,
            top_p=None,
            pad_token_id=tokenizer.eos_token_id,
            eos_token_id=tokenizer.eos_token_id,
        )

    gen_ids = out[0][inputs["input_ids"].shape[-1]:]
    return tokenizer.decode(gen_ids, skip_special_tokens=True).strip()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-model", default="Qwen/Qwen2.5-Coder-3B-Instruct")
    ap.add_argument("--adapter", default=None, help="PEFT LoRA adapter path. Omit for HF base evaluation.")
    ap.add_argument("--test", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--details-out", required=True)
    ap.add_argument("--max-records", type=int, default=None)
    ap.add_argument("--max-new-tokens", type=int, default=256)
    ap.add_argument("--progress-every", type=int, default=10)
    ap.add_argument("--device", choices=["cpu", "mps"], default="cpu")
    args = ap.parse_args()

    records = load_jsonl(args.test)
    if args.max_records:
        records = records[:args.max_records]

    device = args.device
    dtype = torch.float16 if device == "mps" else torch.float32

    print("=" * 80)
    print("HF+PEFT XSSAgent evaluation")
    print(f"base_model={args.base_model}")
    print(f"adapter={args.adapter}")
    print(f"test={args.test}")
    print(f"records={len(records)}")
    print(f"device={device}")
    print("=" * 80)

    tokenizer = AutoTokenizer.from_pretrained(args.base_model, trust_remote_code=True)

    model = AutoModelForCausalLM.from_pretrained(
        args.base_model,
        torch_dtype=dtype,
        device_map=None,
        trust_remote_code=True,
    ).to(device)

    if args.adapter:
        model = PeftModel.from_pretrained(model, args.adapter)
        print(f"loaded adapter: {args.adapter}")

    model.eval()

    results = []
    by_task = {}
    failed_ids = []

    for i, r in enumerate(records, start=1):
        task = r.get("task")
        rid = r.get("id", f"record-{i}")
        expected = extract_expected(r)
        messages = get_prompt_messages(r)

        raw = generate_one(tokenizer, model, messages, args.max_new_tokens)
        parsed = parse_json(raw)
        actual = normalize_actual(task, parsed or {})

        checks = check_record(task, expected, actual)
        passed = all(checks.values())

        results.append({
            "id": rid,
            "task": task,
            "passed": passed,
            "checks": checks,
            "expected": expected,
            "actual": actual,
            "raw_output": raw,
        })

        by_task.setdefault(task, {"total": 0, "passed": 0})
        by_task[task]["total"] += 1
        by_task[task]["passed"] += int(passed)

        if not passed:
            failed_ids.append(rid)

        if args.progress_every and (i % args.progress_every == 0 or i == 1):
            status = "PASS" if passed else "FAIL"
            print(f"[{i:04d}/{len(records):04d}] {status} task={task} id={rid}")

    total = len(results)
    passed = sum(1 for r in results if r["passed"])

    summary_by_task = {}
    for task, stat in by_task.items():
        summary_by_task[task] = {
            "total": stat["total"],
            "passed": stat["passed"],
            "accuracy": stat["passed"] / stat["total"] if stat["total"] else 0.0,
        }

    summary = {
        "summary": {
            "total": total,
            "passed": passed,
            "accuracy": passed / total if total else 0.0,
            "by_task": summary_by_task,
        },
        "failed_ids": failed_ids,
    }

    details = {
        "summary": summary["summary"],
        "results": results,
    }

    write_json(args.out, summary)
    write_json(args.details_out, details)

    print("=" * 80)
    print("DONE")
    print(json.dumps(summary["summary"], ensure_ascii=False, indent=2))
    print(f"out={args.out}")
    print(f"details={args.details_out}")
    print("=" * 80)


if __name__ == "__main__":
    main()
