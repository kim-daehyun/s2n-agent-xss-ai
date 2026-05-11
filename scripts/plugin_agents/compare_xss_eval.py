from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def read_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise FileNotFoundError(f"File not found: {path}")

    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def write_json(data: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def pct(value: float | None) -> float | None:
    if value is None:
        return None

    return round(value * 100, 2)


def get_accuracy(summary: dict[str, Any], task: str | None = None) -> float | None:
    if task is None:
        return summary.get("accuracy")

    by_task = summary.get("by_task", {})
    task_summary = by_task.get(task)

    if not task_summary:
        return None

    return task_summary.get("accuracy")


def main() -> None:
    parser = argparse.ArgumentParser(description="Compare XSSAgent baseline and fine-tuned eval results.")
    parser.add_argument("--baseline", required=True)
    parser.add_argument("--finetuned", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    baseline = read_json(Path(args.baseline))
    finetuned = read_json(Path(args.finetuned))

    baseline_summary = baseline["summary"]
    finetuned_summary = finetuned["summary"]

    tasks = sorted(
        set(baseline_summary.get("by_task", {}).keys())
        | set(finetuned_summary.get("by_task", {}).keys())
    )

    comparison: dict[str, Any] = {
        "baseline_file": args.baseline,
        "finetuned_file": args.finetuned,
        "overall": {},
        "by_task": {},
    }

    baseline_acc = get_accuracy(baseline_summary)
    finetuned_acc = get_accuracy(finetuned_summary)

    comparison["overall"] = {
        "baseline_accuracy": baseline_acc,
        "finetuned_accuracy": finetuned_acc,
        "baseline_accuracy_pct": pct(baseline_acc),
        "finetuned_accuracy_pct": pct(finetuned_acc),
        "delta_pct_point": None
        if baseline_acc is None or finetuned_acc is None
        else round((finetuned_acc - baseline_acc) * 100, 2),
    }

    for task in tasks:
        task_baseline = get_accuracy(baseline_summary, task)
        task_finetuned = get_accuracy(finetuned_summary, task)

        comparison["by_task"][task] = {
            "baseline_accuracy": task_baseline,
            "finetuned_accuracy": task_finetuned,
            "baseline_accuracy_pct": pct(task_baseline),
            "finetuned_accuracy_pct": pct(task_finetuned),
            "delta_pct_point": None
            if task_baseline is None or task_finetuned is None
            else round((task_finetuned - task_baseline) * 100, 2),
        }

    write_json(comparison, Path(args.out))
    print(json.dumps(comparison, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
