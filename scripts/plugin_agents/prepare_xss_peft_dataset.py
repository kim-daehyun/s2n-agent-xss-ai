from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


DEFAULT_INPUT_DIR = Path("data/plugin_agents/xss")
DEFAULT_OUTPUT_DIR = Path("data/plugin_agents/xss_peft")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"Input file not found: {path}")

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


def write_jsonl(records: list[dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")


def validate_messages(record: dict[str, Any], *, source_path: Path, idx: int) -> None:
    messages = record.get("messages")

    if not isinstance(messages, list) or not messages:
        raise ValueError(f"{source_path}:{idx} has no valid messages list")

    roles = [message.get("role") for message in messages]

    for required_role in ["system", "user", "assistant"]:
        if required_role not in roles:
            raise ValueError(f"{source_path}:{idx} has no {required_role} message")

    for message in messages:
        role = message.get("role")
        content = message.get("content")

        if role not in {"system", "user", "assistant"}:
            raise ValueError(f"{source_path}:{idx} has invalid role: {role}")

        if not isinstance(content, str):
            raise ValueError(f"{source_path}:{idx} has non-string content for role={role}")


def convert_record(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": record.get("id"),
        "task": record.get("task"),
        "plugin": record.get("plugin"),
        "agent": record.get("agent"),
        "messages": record["messages"],
    }


def convert_split(input_path: Path, output_path: Path) -> dict[str, Any]:
    records = read_jsonl(input_path)

    converted: list[dict[str, Any]] = []
    by_task: dict[str, int] = {}

    for idx, record in enumerate(records, start=1):
        validate_messages(record, source_path=input_path, idx=idx)

        task = str(record.get("task", "unknown"))
        by_task[task] = by_task.get(task, 0) + 1

        converted.append(convert_record(record))

    write_jsonl(converted, output_path)

    return {
        "input": str(input_path),
        "output": str(output_path),
        "count": len(converted),
        "by_task": by_task,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Prepare XSSAgent ChatML dataset for PEFT LoRA fine-tuning."
    )
    parser.add_argument("--input-dir", default=str(DEFAULT_INPUT_DIR))
    parser.add_argument("--out-dir", default=str(DEFAULT_OUTPUT_DIR))
    args = parser.parse_args()

    input_dir = Path(args.input_dir)
    out_dir = Path(args.out_dir)

    summaries = []

    for split in ["train", "valid", "test"]:
        summaries.append(
            convert_split(
                input_path=input_dir / f"{split}.jsonl",
                output_path=out_dir / f"{split}.jsonl",
            )
        )

    print(json.dumps({"prepared": summaries}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
