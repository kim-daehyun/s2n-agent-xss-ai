"""
Fenrir v2.1 데이터셋 다운로드 + 필터링 + 포맷 변환 스크립트.

HuggingFace: AlicanKiraz0/Cybersecurity-Dataset-Fenrir-v2.1 (99,870 샘플)
→ 웹 취약점 관련 샘플 필터링 (~5,000-15,000개 예상)
→ messages 포맷으로 변환 (mlx-lm 호환)
→ 기존 train.jsonl과 혼합 (선택)

사용법:
    # 기본: data/fenrir_web.jsonl 생성
    python3 scripts/fetch_fenrir.py

    # 최대 샘플 수 제한
    python3 scripts/fetch_fenrir.py --max-samples 3000

    # 기존 train.jsonl 과 혼합하여 data/train_mixed.jsonl 생성
    python3 scripts/fetch_fenrir.py --merge

    # 혼합 비율 조정 (기존:fenrir = 1:2)
    python3 scripts/fetch_fenrir.py --merge --ratio 0.33

    # 이미 다운로드된 캐시 재사용 (네트워크 없이)
    python3 scripts/fetch_fenrir.py --offline

필요 패키지:
    pip install datasets huggingface_hub
"""

from __future__ import annotations

import argparse
import json
import random
import re
import sys
from pathlib import Path

# ── 설정 ─────────────────────────────────────────────────────────────────────

DATASET_ID = "AlicanKiraz0/Cybersecurity-Dataset-Fenrir-v2.1"
OUT_DIR = Path("data")
CACHE_PATH = OUT_DIR / "fenrir_web.jsonl"
SPLIT = "train"

# 웹 취약점 관련 키워드 (대소문자 무관)
_WEB_KEYWORDS = [
    # 웹 공격 유형
    r"\bxss\b", r"cross[\s-]site scripting",
    r"\bsql[\s]?inject", r"\bsqli\b",
    r"\bcsrf\b", r"cross[\s-]site request",
    r"command inject", r"os command", r"shell inject",
    r"path traversal", r"directory traversal", r"lfi\b", r"rfi\b",
    r"file upload", r"unrestricted upload",
    r"\bjwt\b", r"json web token",
    r"brute[\s-]force", r"credential stuffing",
    r"ssrf\b", r"server[\s-]side request",
    r"xxe\b", r"xml external",
    r"deserialization", r"insecure deserializ",
    r"open redirect",
    r"clickjacking",
    r"\bidor\b", r"insecure direct object",
    r"mass assignment",
    # 웹 프레임워크 / 도구
    r"owasp", r"burp suite", r"web application",
    r"payload", r"exploit", r"poc\b",
    # 스캐닝 관련
    r"vulnerability scan", r"pentest", r"penetration test",
    r"false positive", r"fp reduction",
    # 웹 기술
    r"http header", r"cookie security", r"cors\b",
    r"content security policy", r"\bcsp\b",
    r"input validation", r"output encoding",
    r"sanitiz", r"escap",
]

# 제외 키워드 (네트워크/하드웨어/OT 등 웹과 무관한 내용)
_EXCLUDE_KEYWORDS = [
    r"industrial control", r"\bscada\b", r"\bplc\b",
    r"physical security", r"cctv\b",
    r"iot firmware", r"hardware security module(?! key)",  # HSM은 웹에서도 나옴
    r"rf jamming", r"bluetooth attack",
]

_WEB_RE = re.compile("|".join(_WEB_KEYWORDS), re.IGNORECASE)
_EXCL_RE = re.compile("|".join(_EXCLUDE_KEYWORDS), re.IGNORECASE)


# ── 필터링 ────────────────────────────────────────────────────────────────────

def is_web_relevant(row: dict) -> bool:
    """user + assistant 텍스트에서 웹 취약점 관련 여부 판별."""
    text = f"{row.get('user', '')} {row.get('assistant', '')}"
    if _EXCL_RE.search(text):
        return False
    return bool(_WEB_RE.search(text))


# ── 포맷 변환 ─────────────────────────────────────────────────────────────────

_DEFAULT_SYSTEM = (
    "You are S2N-Agent, a specialized AI for web vulnerability scanning. "
    "You analyze web application context, select security test plugins, "
    "plan attack payloads, filter false positives, and plan multi-step scans. "
    "Always respond with accurate, actionable cybersecurity guidance."
)


def to_messages_format(row: dict) -> dict:
    """
    Fenrir {system, user, assistant} → mlx-lm messages 포맷.

    {
      "messages": [
        {"role": "system",    "content": "..."},
        {"role": "user",      "content": "..."},
        {"role": "assistant", "content": "..."}
      ]
    }
    """
    system = row.get("system") or _DEFAULT_SYSTEM
    return {
        "messages": [
            {"role": "system",    "content": system.strip()},
            {"role": "user",      "content": row["user"].strip()},
            {"role": "assistant", "content": row["assistant"].strip()},
        ]
    }


# ── 메인 ─────────────────────────────────────────────────────────────────────

def fetch_and_filter(
    max_samples: int = 0,
    offline: bool = False,
    seed: int = 42,
) -> list[dict]:
    """데이터셋 로드 → 필터링 → messages 변환."""
    try:
        from datasets import load_dataset
    except ImportError:
        print("[오류] datasets 미설치: pip install datasets huggingface_hub")
        sys.exit(1)

    print(f"데이터셋 로드 중: {DATASET_ID}")
    if offline:
        ds = load_dataset(DATASET_ID, split=SPLIT, download_mode="reuse_cache_if_exists")
    else:
        ds = load_dataset(DATASET_ID, split=SPLIT)

    total = len(ds)
    print(f"전체 샘플: {total:,}개  필터링 중...")

    filtered: list[dict] = []
    for i, row in enumerate(ds):
        if is_web_relevant(row):
            filtered.append(to_messages_format(row))
        if (i + 1) % 10_000 == 0:
            print(f"  진행: {i+1:,}/{total:,}  (현재 필터 통과: {len(filtered):,})")

    print(f"필터 통과: {len(filtered):,}개 / {total:,}개 ({len(filtered)/total:.1%})")

    if max_samples > 0 and len(filtered) > max_samples:
        random.seed(seed)
        random.shuffle(filtered)
        filtered = filtered[:max_samples]
        print(f"max_samples 제한 적용: {len(filtered):,}개")

    return filtered


def merge_datasets(
    existing_path: Path,
    fenrir_samples: list[dict],
    ratio: float,
    seed: int = 42,
) -> list[dict]:
    """
    기존 데이터 + Fenrir 혼합.

    ratio: Fenrir 비율 (0.0~1.0).
           ratio=0.5 → 기존 50% + Fenrir 50%
    기본 권장: ratio=0.4 (기존 데이터 task-specific 우선)
    """
    # 기존 train + valid + test 모두 합산 (전체 혼합 후 재분리)
    existing: list[dict] = []
    base_dir = existing_path.parent
    for part in ("train.jsonl", "valid.jsonl", "test.jsonl"):
        p = base_dir / part
        if p.exists():
            with p.open(encoding="utf-8") as f:
                existing.extend(json.loads(line) for line in f)
    if not existing:
        with existing_path.open(encoding="utf-8") as f:
            existing = [json.loads(line) for line in f]

    total_existing = len(existing)
    fenrir_n = min(len(fenrir_samples), int((total_existing + len(fenrir_samples)) * ratio))

    random.seed(seed)
    fenrir_sample = random.sample(fenrir_samples, min(fenrir_n, len(fenrir_samples)))

    mixed = existing + fenrir_sample
    random.shuffle(mixed)

    print(f"\n혼합 결과:")
    print(f"  기존 데이터  : {total_existing:,}개")
    print(f"  Fenrir 데이터: {len(fenrir_sample):,}개")
    print(f"  합계         : {len(mixed):,}개")
    return mixed


def split_and_save(
    mixed: list[dict],
    out_dir: Path,
    train_ratio: float = 0.80,
    valid_ratio: float = 0.10,
    seed: int = 42,
) -> None:
    """혼합 데이터를 train/valid/test 로 분리하여 저장."""
    random.seed(seed)
    data = mixed[:]
    random.shuffle(data)

    n = len(data)
    n_train = int(n * train_ratio)
    n_valid = int(n * valid_ratio)

    splits = {
        "train.jsonl": data[:n_train],
        "valid.jsonl": data[n_train: n_train + n_valid],
        "test.jsonl":  data[n_train + n_valid:],
    }

    out_dir.mkdir(parents=True, exist_ok=True)
    for fname, samples in splits.items():
        p = out_dir / fname
        with p.open("w", encoding="utf-8") as f:
            for s in samples:
                f.write(json.dumps(s, ensure_ascii=False) + "\n")
        print(f"  {fname}: {len(samples):,}개 → {p}")


def write_config(out_dir: Path, base_config: Path = Path("configs/lora_3b.yaml")) -> Path:
    """data_dir를 참조하는 새 학습 config 생성."""
    try:
        import yaml
    except ImportError:
        print("[경고] pyyaml 미설치 — config 자동 생성 건너뜀: pip install pyyaml")
        return base_config

    if not base_config.exists():
        return base_config

    with base_config.open() as f:
        cfg = yaml.safe_load(f)

    cfg["data"] = str(out_dir)
    cfg["adapter_path"] = "lora-out/3b-fenrir"

    new_config = Path("configs/lora_3b_fenrir.yaml")
    with new_config.open("w") as f:
        yaml.dump(cfg, f, default_flow_style=False, allow_unicode=True)

    print(f"  학습 config 생성: {new_config}")
    return new_config


def save_jsonl(samples: list[dict], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for s in samples:
            f.write(json.dumps(s, ensure_ascii=False) + "\n")
    print(f"저장 완료: {path}  ({len(samples):,}개)")


# ── 진입점 ────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Fenrir v2.1 데이터셋 필터링 + 변환")
    parser.add_argument("--output", default=str(CACHE_PATH),
                        help="필터링된 샘플 출력 경로 (기본: data/fenrir_web.jsonl)")
    parser.add_argument("--max-samples", type=int, default=0,
                        help="최대 샘플 수 (0=전체 필터 결과)")
    parser.add_argument("--merge", action="store_true",
                        help="기존 train.jsonl과 혼합하여 train_mixed.jsonl 생성")
    parser.add_argument("--train-file", default="data/train.jsonl",
                        help="혼합할 기존 학습 파일 (기본: data/train.jsonl)")
    parser.add_argument("--ratio", type=float, default=0.40,
                        help="혼합 시 Fenrir 비율 (기본: 0.40 = 40%%)")
    parser.add_argument("--offline", action="store_true",
                        help="HuggingFace 캐시 재사용 (네트워크 없이)")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    out_path = Path(args.output)

    # 1. 다운로드 + 필터링
    if out_path.exists() and args.offline:
        print(f"캐시 재사용: {out_path}")
        with out_path.open(encoding="utf-8") as f:
            fenrir_samples = [json.loads(line) for line in f]
        print(f"로드: {len(fenrir_samples):,}개")
    else:
        fenrir_samples = fetch_and_filter(
            max_samples=args.max_samples,
            offline=args.offline,
            seed=args.seed,
        )
        save_jsonl(fenrir_samples, out_path)

    # 2. 혼합 + 분리 (선택)
    if args.merge:
        train_path = Path(args.train_file)
        if not train_path.exists():
            print(f"[경고] 기존 train 파일 없음: {train_path}")
            print("  --merge 없이 fenrir_web.jsonl만 생성합니다.")
        else:
            mixed = merge_datasets(
                existing_path=train_path,
                fenrir_samples=fenrir_samples,
                ratio=args.ratio,
                seed=args.seed,
            )
            mixed_dir = Path("data_mixed")
            print(f"\ntrain/valid/test 분리 → {mixed_dir}/")
            split_and_save(mixed, out_dir=mixed_dir, seed=args.seed)
            cfg_path = write_config(mixed_dir)
            print(f"\n다음 단계:")
            print(f"  python3 scripts/train.py --config {cfg_path}")
    else:
        print(f"\n다음 단계:")
        print(f"  # 기존 데이터와 혼합 후 학습:")
        print(f"  python3 scripts/fetch_fenrir.py --merge")
        print(f"  # Fenrir만으로 별도 학습:")
        print(f"  # (먼저 data_fenrir/ 디렉토리를 직접 구성하세요)")


if __name__ == "__main__":
    main()
