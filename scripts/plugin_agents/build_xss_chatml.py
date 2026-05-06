from __future__ import annotations

import argparse
import json
import random
from collections import defaultdict
from pathlib import Path
from typing import Any

from _utils import read_jsonl, write_jsonl


# Must match XSSAgent.system_prompt in s2nagent/plugin_agents/xss.py exactly.
SYSTEM_PROMPT = (
    "You are XSSAgent, the dedicated S2N-Agent model for Cross-Site Scripting scan decisions. "
    "Return strict JSON only. "
    "You do not send HTTP requests, manage cookies, execute JavaScript, or parse full DOM trees. "
    "Your job is to decide whether the S2N xss plugin should run, plan context-aware authorized "
    "scanner validation inputs, filter false positives, and suggest the next scan action. "
    "Use the requested JSON schema exactly."
)


def build_user_prompt(record: dict[str, Any]) -> str:
    task = record["task"]

    payload = {
        "id": record["id"],
        "plugin": record["plugin"],
        "agent": record["agent"],
        "task": task,
        "context": record.get("context", {}),
        "evidence": record.get("evidence", {}),
    }

    if task == "selection":
        return (
            "Decide whether the xss plugin should run for this web context. "
            "Return strict JSON only with keys: plugin, should_run, confidence, reason.\n"
            + json.dumps(payload, ensure_ascii=False)
        )

    if task == "payload_planning":
        return (
            "Generate an XSS payload planning object for this injection context. "
            "Return strict JSON only with keys: payloads, bypass_variants, strategy, context_notes.\n"
            + json.dumps(payload, ensure_ascii=False)
        )

    if task == "false_positive":
        return (
            "Decide whether this XSS finding is confirmed, likely false positive, or inconclusive. "
            "Return strict JSON only with keys: verdict, reason, confidence.\n"
            + json.dumps(payload, ensure_ascii=False)
        )

    if task == "next_action":
        return (
            "Suggest the next scanner action after XSS analysis. "
            "Return strict JSON only with keys: next_action, reason, priority.\n"
            + json.dumps(payload, ensure_ascii=False)
        )

    raise ValueError(f"Unsupported task: {task}")


def build_reason(record: dict[str, Any]) -> str:
    task = record["task"]
    expected = record["expected_json"]

    if task == "selection":
        if expected.get("should_run") is True:
            context = expected.get("injection_context", "unknown")
            parameter = expected.get("parameter", "unknown")
            return f"User-controlled parameter '{parameter}' is reflected in {context} context"

        return f"XSS should not run because this looks like {expected.get('reason_type', 'insufficient evidence')}"

    if task == "next_action":
        return f"Expected follow-up action is {expected.get('next_action')} based on completed plugins, findings, and sitemap"

    if task == "false_positive":
        return f"Expected verdict based on {expected.get('reason_type', 'provided evidence')}"

    return "Expected output follows the provided evidence and task contract"


def build_assistant_output(record: dict[str, Any]) -> str:
    task = record["task"]
    expected = record["expected_json"]

    if task == "selection":
        output = {
            "plugin": expected.get("plugin", "xss"),
            "should_run": expected["should_run"],
            "confidence": expected.get(
                "confidence_min",
                30 if expected["should_run"] is False else 80,
            ),
            "reason": build_reason(record),
        }
        return json.dumps(output, ensure_ascii=False)

    if task == "payload_planning":
        output = {
            "payloads": expected.get("payloads", []),
            "bypass_variants": expected.get("bypass_variants", []),
            "strategy": expected.get("strategy", ""),
            "context_notes": expected.get("context_notes", ""),
        }
        return json.dumps(output, ensure_ascii=False)

    if task == "false_positive":
        output = {
            "verdict": expected["verdict"],
            "reason": build_reason(record),
            "confidence": expected.get("confidence_min", 75),
        }
        return json.dumps(output, ensure_ascii=False)

    if task == "next_action":
        output = {
            "next_action": expected["next_action"],
            "reason": build_reason(record),
            "priority": expected.get("priority", "medium"),
        }
        return json.dumps(output, ensure_ascii=False)

    raise ValueError(f"Unsupported task: {task}")


def to_chatml(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": record["id"],
        "task": record["task"],
        "plugin": record["plugin"],
        "agent": record["agent"],
        "expected_json": record["expected_json"],
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": build_user_prompt(record)},
            {"role": "assistant", "content": build_assistant_output(record)},
        ],
    }


def stratified_split_records(
    records: list[dict[str, Any]],
    *,
    train_ratio: float,
    valid_ratio: float,
    seed: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    if train_ratio <= 0 or valid_ratio < 0 or train_ratio + valid_ratio >= 1:
        raise ValueError("Invalid split ratios. Require train_ratio > 0, valid_ratio >= 0, train+valid < 1.")

    by_task: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        by_task[record["task"]].append(record)

    rng = random.Random(seed)

    train: list[dict[str, Any]] = []
    valid: list[dict[str, Any]] = []
    test: list[dict[str, Any]] = []

    for task, task_records in sorted(by_task.items()):
        shuffled = task_records[:]
        rng.shuffle(shuffled)

        total = len(shuffled)
        train_end = int(total * train_ratio)
        valid_end = train_end + int(total * valid_ratio)

        train.extend(shuffled[:train_end])
        valid.extend(shuffled[train_end:valid_end])
        test.extend(shuffled[valid_end:])

    rng.shuffle(train)
    rng.shuffle(valid)
    rng.shuffle(test)

    return train, valid, test


def summarize(records: list[dict[str, Any]]) -> dict[str, int]:
    summary: dict[str, int] = {}
    for record in records:
        summary[record["task"]] = summary.get(record["task"], 0) + 1
    return summary


def main() -> None:
    parser = argparse.ArgumentParser(description="Convert XSSAgent raw JSONL samples into ChatML train/valid/test JSONL files.")
    parser.add_argument("--input", default="data/plugin_agents/xss/raw.jsonl")
    parser.add_argument("--out-dir", default="data/plugin_agents/xss")
    parser.add_argument("--train-ratio", type=float, default=0.8)
    parser.add_argument("--valid-ratio", type=float, default=0.1)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    raw_records = read_jsonl(Path(args.input))
    chatml_records = [to_chatml(record) for record in raw_records]

    train, valid, test = stratified_split_records(
        chatml_records,
        train_ratio=args.train_ratio,
        valid_ratio=args.valid_ratio,
        seed=args.seed,
    )

    out_dir = Path(args.out_dir)
    write_jsonl(train, out_dir / "train.jsonl")
    write_jsonl(valid, out_dir / "valid.jsonl")
    write_jsonl(test, out_dir / "test.jsonl")

    print(f"input records: {len(raw_records)}")
    print(f"train records: {len(train)}")
    print(f"valid records: {len(valid)}")
    print(f"test records: {len(test)}")
    print("split by task:")
    print(json.dumps(
        {
            "train": summarize(train),
            "valid": summarize(valid),
            "test": summarize(test),
        },
        ensure_ascii=False,
        indent=2,
    ))
    print(f"wrote files to {out_dir}")


if __name__ == "__main__":
    main()