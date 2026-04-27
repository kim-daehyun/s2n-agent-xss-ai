"""
학습 데이터 train/val/test 분리.

mlx-lm은 data 디렉토리 안에 train.jsonl / valid.jsonl 을 기대합니다.
test.jsonl은 evaluate.py에서 사용합니다.

사용법:
    python3 scripts/split_data.py
    python3 scripts/split_data.py --input data/train.jsonl --val-ratio 0.1 --test-ratio 0.1
"""

from __future__ import annotations

import argparse
import json
import random
from pathlib import Path


def split(
    input_path: str = "data/train.jsonl",
    val_ratio: float = 0.1,
    test_ratio: float = 0.1,
    seed: int = 42,
) -> None:
    src = Path(input_path)
    out_dir = src.parent

    with src.open(encoding="utf-8") as f:
        samples = [json.loads(line) for line in f]

    random.seed(seed)
    random.shuffle(samples)

    n = len(samples)
    n_test = int(n * test_ratio)
    n_val = int(n * val_ratio)
    n_train = n - n_val - n_test

    splits = {
        "train.jsonl": samples[:n_train],
        "valid.jsonl": samples[n_train : n_train + n_val],   # mlx-lm 규약
        "test.jsonl":  samples[n_train + n_val :],
    }

    for filename, data in splits.items():
        dest = out_dir / filename
        with dest.open("w", encoding="utf-8") as f:
            for s in data:
                f.write(json.dumps(s, ensure_ascii=False) + "\n")
        print(f"  {filename:15s} → {len(data):5d} samples  ({dest})")

    print(f"\n합계: {n}  train={n_train}  val={n_val}  test={n_test}")

    # 태스크별 분포 확인
    print("\n[train 태스크 분포]")
    from collections import Counter
    task_counts = Counter(
        s["messages"][0]["content"][:40] for s in splits["train.jsonl"]
    )
    for k, v in sorted(task_counts.items(), key=lambda x: -x[1]):
        print(f"  [{v:4d}]  {k}...")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="train/val/test 데이터 분리")
    parser.add_argument("--input", default="data/train.jsonl")
    parser.add_argument("--val-ratio", type=float, default=0.1)
    parser.add_argument("--test-ratio", type=float, default=0.1)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    split(args.input, args.val_ratio, args.test_ratio, args.seed)
