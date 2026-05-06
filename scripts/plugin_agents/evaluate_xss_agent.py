from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

from s2nagent.plugin_agents.registry import get_plugin_agent


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []

    with path.open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue

            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON at {path}:{line_no}: {exc}") from exc

    return records


def write_json(data: dict[str, Any], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def format_seconds(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f}s"

    minutes = int(seconds // 60)
    remaining = seconds % 60
    return f"{minutes}m {remaining:.1f}s"


def extract_user_payload(chatml_record: dict[str, Any]) -> dict[str, Any]:
    user_content = chatml_record["messages"][1]["content"]

    start = user_content.find("{")
    end = user_content.rfind("}")

    if start < 0 or end <= start:
        raise ValueError(f"Cannot extract JSON payload from record {chatml_record.get('id')}")

    return json.loads(user_content[start : end + 1])


def get_expected_from_chatml(chatml_record: dict[str, Any]) -> dict[str, Any]:
    """
    build_xss_chatml.py에서 assistant message에 넣은 expected output을 읽는다.
    """
    assistant_content = chatml_record["messages"][2]["content"]
    return json.loads(assistant_content)


def run_selection(agent: Any, payload: dict[str, Any]) -> dict[str, Any]:
    context = payload.get("context", {})
    evidence = payload.get("evidence", {})

    decision = agent.evaluate_target(
        url=context.get("url", ""),
        dom=context.get("dom", ""),
        sitemap_summary=context.get("sitemap_summary", ""),
        response_snippet=evidence.get("response_snippet", ""),
    )

    data = decision.model_dump()
    data["_actual_task_output"] = data.get("task_outputs", {}).get("selection", {})
    data["_actual_context"] = data.get("context", {})
    return data


def run_payload_planning(agent: Any, payload: dict[str, Any]) -> dict[str, Any]:
    context = payload.get("context", {})
    evidence = payload.get("evidence", {})

    return agent.plan_payloads(
        parameter=context.get("parameter", "q"),
        context=context.get("injection_context", "unknown"),
        dom_snippet=context.get("dom_snippet", ""),
        response_snippet=evidence.get("response_snippet", ""),
    )


def run_false_positive(agent: Any, payload: dict[str, Any]) -> dict[str, Any]:
    context = payload.get("context", {})
    evidence = payload.get("evidence", {})

    return agent.filter_false_positive(
        finding=context.get("finding", "Possible XSS"),
        evidence=evidence.get("evidence", ""),
        response_body=evidence.get("response_body", ""),
    )


def run_next_action(agent: Any, payload: dict[str, Any]) -> dict[str, Any]:
    context = payload.get("context", {})

    return agent.plan_next_action(
        completed=context.get("completed", []),
        findings=context.get("findings", []),
        sitemap=context.get("sitemap", ""),
    )


def is_payload_schema_valid(actual: dict[str, Any]) -> bool:
    return (
        isinstance(actual, dict)
        and isinstance(actual.get("payloads"), list)
        and "strategy" in actual
        and "context_notes" in actual
        and "bypass_variants" in actual
    )


def evaluate_record(agent: Any, record: dict[str, Any]) -> dict[str, Any]:
    task = record["task"]
    payload = extract_user_payload(record)
    expected = get_expected_from_chatml(record)

    result: dict[str, Any] = {
        "id": record.get("id"),
        "task": task,
        "passed": False,
        "actual": None,
        "expected": expected,
        "checks": {},
    }

    try:
        if task == "selection":
            actual = run_selection(agent, payload)
            selection = actual.get("_actual_task_output", {})
            actual_context = actual.get("_actual_context", {})

            expected_should_run = expected.get("should_run")
            actual_should_run = actual.get("should_run")

            result["actual"] = actual
            result["checks"] = {
                "should_run": actual_should_run == expected_should_run,
                "plugin": selection.get("plugin") == expected.get("plugin", "xss"),
                "context_known": actual_context.get("injection_context") != "unknown",
            }

            result["passed"] = all(result["checks"].values())
            return result

        if task == "payload_planning":
            actual = run_payload_planning(agent, payload)

            result["actual"] = actual
            result["checks"] = {
                "schema_valid": is_payload_schema_valid(actual),
                "has_payloads": bool(actual.get("payloads")),
                "has_strategy": bool(actual.get("strategy")),
                "has_context_notes": bool(actual.get("context_notes")),
            }

            result["passed"] = all(result["checks"].values())
            return result

        if task == "false_positive":
            actual = run_false_positive(agent, payload)

            result["actual"] = actual
            result["checks"] = {
                "verdict": actual.get("verdict") == expected.get("verdict"),
                "confidence_present": isinstance(actual.get("confidence"), int),
                "reason_present": bool(actual.get("reason")),
            }

            result["passed"] = all(result["checks"].values())
            return result

        if task == "next_action":
            actual = run_next_action(agent, payload)

            result["actual"] = actual
            result["checks"] = {
                "next_action": actual.get("next_action") == expected.get("next_action"),
                "priority": actual.get("priority") == expected.get("priority"),
                "reason_present": bool(actual.get("reason")),
            }

            result["passed"] = all(result["checks"].values())
            return result

        result["actual"] = {"error": f"unsupported task: {task}"}
        return result

    except Exception as exc:
        result["actual"] = {
            "error": type(exc).__name__,
            "message": str(exc),
        }
        return result


def evaluate_records_with_progress(
    *,
    agent: Any,
    records: list[dict[str, Any]],
    progress_every: int = 1,
) -> list[dict[str, Any]]:
    total = len(records)
    results: list[dict[str, Any]] = []

    if total == 0:
        return results

    started_at = time.time()

    for idx, record in enumerate(records, start=1):
        record_id = record.get("id", "unknown")
        task = record.get("task", "unknown")

        result = evaluate_record(agent, record)
        results.append(result)

        should_print = (
            progress_every > 0
            and (idx == 1 or idx == total or idx % progress_every == 0)
        )

        if should_print:
            elapsed = time.time() - started_at
            avg_per_item = elapsed / idx
            remaining = avg_per_item * (total - idx)
            percent = (idx / total) * 100
            status = "PASS" if result.get("passed") else "FAIL"

            print(
                f"[{idx:04d}/{total:04d}] "
                f"{percent:6.2f}% "
                f"{status} "
                f"task={task} "
                f"id={record_id} "
                f"elapsed={format_seconds(elapsed)} "
                f"eta={format_seconds(remaining)}"
            )

    return results


def summarize(results: list[dict[str, Any]]) -> dict[str, Any]:
    total = len(results)
    passed = sum(1 for item in results if item["passed"])

    by_task: dict[str, dict[str, Any]] = {}

    for item in results:
        task = item["task"]
        bucket = by_task.setdefault(
            task,
            {
                "total": 0,
                "passed": 0,
                "accuracy": 0.0,
            },
        )

        bucket["total"] += 1
        if item["passed"]:
            bucket["passed"] += 1

    for bucket in by_task.values():
        bucket["accuracy"] = bucket["passed"] / bucket["total"] if bucket["total"] else 0.0

    return {
        "total": total,
        "passed": passed,
        "accuracy": passed / total if total else 0.0,
        "by_task": by_task,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate XSSAgent against ChatML test records.")
    parser.add_argument("--test", default="data/plugin_agents/xss/test.jsonl")
    parser.add_argument("--out", default="reports/xss_agent/baseline_eval.json")
    parser.add_argument("--details-out", default="reports/xss_agent/baseline_eval_details.json")
    parser.add_argument(
        "--progress-every",
        type=int,
        default=1,
        help="Print progress every N records. Use 0 to disable progress output.",
    )
    args = parser.parse_args()

    agent = get_plugin_agent("xss")
    if agent is None:
        raise RuntimeError("xss agent not found in registry")

    records = read_jsonl(Path(args.test))

    print(f"loaded {len(records)} test records from {args.test}")
    print("starting XSSAgent evaluation...")

    results = evaluate_records_with_progress(
        agent=agent,
        records=records,
        progress_every=args.progress_every,
    )

    report = {
        "summary": summarize(results),
        "failed_ids": [item["id"] for item in results if not item["passed"]],
    }

    write_json(report, Path(args.out))
    write_json({"results": results}, Path(args.details_out))

    print("\n" + "=" * 80)
    print("Evaluation summary")
    print("=" * 80)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print(f"wrote summary to {args.out}")
    print(f"wrote details to {args.details_out}")


if __name__ == "__main__":
    main()