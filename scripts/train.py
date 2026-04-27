"""
S2N-Agent LoRA 학습 스크립트 (mlx-lm 래퍼).

사용법:
    # 3B 실험
    python3 scripts/train.py --config configs/lora_3b.yaml

    # 7B 실전
    python3 scripts/train.py --config configs/lora_7b.yaml

    # 재개 (체크포인트에서)
    python3 scripts/train.py --config configs/lora_3b.yaml --resume

mlx-lm 설치:
    pip install mlx-lm
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path


def _check_mlx() -> bool:
    try:
        import mlx_lm  # noqa: F401
        return True
    except ImportError:
        return False


def _install_mlx() -> None:
    print("mlx-lm 미설치 — 설치를 시도합니다...")
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "mlx-lm", "-q"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print("자동 설치 실패. 수동으로 실행하세요:")
        print("  pip install mlx-lm")
        sys.exit(1)
    print("mlx-lm 설치 완료.")


def _verify_data(data_dir: Path) -> None:
    """train.jsonl / valid.jsonl 존재 확인."""
    for name in ("train.jsonl", "valid.jsonl"):
        p = data_dir / name
        if not p.exists():
            print(f"[오류] {p} 없음 — 먼저 split_data.py 실행 필요:")
            print("  python3 scripts/split_data.py")
            sys.exit(1)
        n = sum(1 for _ in p.open())
        print(f"  {name}: {n} samples")


def run_training(config_path: str, resume: bool = False) -> None:
    import yaml  # type: ignore

    cfg_path = Path(config_path)
    if not cfg_path.exists():
        print(f"[오류] config 파일 없음: {cfg_path}")
        sys.exit(1)

    with cfg_path.open() as f:
        cfg = yaml.safe_load(f)

    model_id: str = cfg["model"]
    adapter_out: str = cfg.get("adapter_path", "lora-out/default")
    data_dir = Path(cfg.get("data", "data"))

    print("=" * 60)
    print(f"S2N-Agent LoRA 학습")
    print(f"  모델    : {model_id}")
    print(f"  설정    : {cfg_path}")
    print(f"  Adapter : {adapter_out}")
    print(f"  데이터  : {data_dir}/")
    print("=" * 60)

    _verify_data(data_dir)

    # mlx-lm lora 명령 구성
    cmd = [
        sys.executable, "-m", "mlx_lm.lora",
        "--config", str(cfg_path),
    ]
    if resume:
        cmd += ["--resume-adapter-file", f"{adapter_out}/adapters.npz"]

    print(f"\n실행: {' '.join(cmd)}\n")
    start = time.time()

    try:
        proc = subprocess.run(cmd)
        elapsed = time.time() - start
        if proc.returncode == 0:
            print(f"\n학습 완료 ({elapsed/60:.1f}분)")
            print(f"Adapter 저장 위치: {adapter_out}/")
            _post_train_summary(adapter_out)
        else:
            print(f"\n학습 실패 (exit={proc.returncode})")
            sys.exit(proc.returncode)
    except KeyboardInterrupt:
        print("\n학습 중단 (Ctrl+C)")


def _post_train_summary(adapter_dir: str) -> None:
    """학습 완료 후 저장된 파일 목록 출력."""
    p = Path(adapter_dir)
    if not p.exists():
        return
    files = list(p.glob("*"))
    print(f"\n[저장된 파일 ({len(files)}개)]")
    for f in sorted(files):
        size_kb = f.stat().st_size // 1024
        print(f"  {f.name:30s}  {size_kb:6d} KB")
    print("\n다음 단계:")
    print("  1. 평가:  python3 scripts/evaluate.py --adapter", adapter_dir)
    print("  2. 배포:  bash scripts/deploy_ollama.sh", adapter_dir)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="S2N-Agent LoRA 학습")
    parser.add_argument("--config", default="configs/lora_3b.yaml", help="학습 설정 YAML")
    parser.add_argument("--resume", action="store_true", help="기존 adapter에서 재개")
    parser.add_argument("--install-deps", action="store_true", help="mlx-lm 자동 설치")
    args = parser.parse_args()

    if not _check_mlx():
        if args.install_deps:
            _install_mlx()
        else:
            print("[오류] mlx-lm 미설치. 다음 중 하나 실행:")
            print("  pip install mlx-lm")
            print("  python3 scripts/train.py --config ... --install-deps")
            sys.exit(1)

    # yaml 의존성 확인
    try:
        import yaml  # noqa: F401
    except ImportError:
        subprocess.run([sys.executable, "-m", "pip", "install", "pyyaml", "-q"])

    run_training(args.config, resume=args.resume)
