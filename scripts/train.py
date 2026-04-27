"""
S2N-Agent LoRA 학습 스크립트 (mlx-lm 래퍼).

개선 사항 (v2):
  - Early stopping: val loss가 patience 내에 개선 없으면 자동 중단
  - Best checkpoint 선택: 학습 후 최저 val loss 체크포인트를 best_adapters.npz로 복사
  - --epochs 옵션: iters를 데이터셋 크기 기반으로 동적 계산
  - M1 메모리 감지: 16GB 이상이면 batch_size 자동 상향
  - val loss 곡선 출력: 학습 후 요약 그래프

사용법:
    # 기본 (config iters 사용)
    python3 scripts/train.py --config configs/lora_3b.yaml

    # epoch 기반 (권장 — 데이터 크기 자동 반영)
    python3 scripts/train.py --config configs/lora_3b.yaml --epochs 5

    # early stopping patience 조정 (기본: val 체크 5회 연속 미개선 시 중단)
    python3 scripts/train.py --config configs/lora_3b.yaml --epochs 6 --patience 7

    # 체크포인트에서 재개
    python3 scripts/train.py --config configs/lora_3b.yaml --resume
"""

from __future__ import annotations

import argparse
import math
import re
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

# ── 상수 ─────────────────────────────────────────────────────────────────────

# mlx-lm val loss 출력 패턴:
# "Iter 200: Val loss 0.5431, Val took 3.24s"
_VAL_RE = re.compile(r"Iter\s+(\d+):\s+Val loss\s+([\d.]+)")

# 학습 loss 패턴:
# "Iter 50: Train loss 1.2345, Learning Rate 2.000e-04, It/sec 1.23, ..."
_TRAIN_RE = re.compile(r"Iter\s+(\d+):\s+Train loss\s+([\d.]+)")


# ── mlx-lm 존재 확인 ──────────────────────────────────────────────────────────

def _check_mlx() -> bool:
    try:
        import mlx_lm  # noqa: F401
        return True
    except ImportError:
        return False


def _install_mlx() -> None:
    print("mlx-lm 미설치 — 설치 중...")
    result = subprocess.run(
        [sys.executable, "-m", "pip", "install", "mlx-lm", "-q"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print("자동 설치 실패. 수동 실행: pip install mlx-lm")
        sys.exit(1)
    print("mlx-lm 설치 완료.")


# ── 데이터 확인 ───────────────────────────────────────────────────────────────

def _count_samples(path: Path) -> int:
    if not path.exists():
        return 0
    with path.open(encoding="utf-8") as f:
        return sum(1 for _ in f)


def _verify_data(data_dir: Path) -> dict[str, int]:
    counts = {}
    for name in ("train.jsonl", "valid.jsonl"):
        p = data_dir / name
        if not p.exists():
            print(f"[오류] {p} 없음 — 먼저 split_data.py 실행:")
            print("  python3 scripts/split_data.py")
            sys.exit(1)
        counts[name] = _count_samples(p)
        print(f"  {name}: {counts[name]:,} samples")
    return counts


# ── M1 메모리 감지 ────────────────────────────────────────────────────────────

def _get_memory_gb() -> float:
    """Apple Silicon 통합 메모리 크기(GB) 반환. 실패 시 0."""
    try:
        out = subprocess.check_output(
            ["sysctl", "-n", "hw.memsize"], text=True
        ).strip()
        return int(out) / (1024 ** 3)
    except Exception:
        return 0.0


def _suggest_batch_size(cfg_batch: int, mem_gb: float, model_size: str) -> int:
    """메모리 크기와 모델 크기에 따라 batch_size 추천."""
    if mem_gb <= 0:
        return cfg_batch
    is_7b = "7b" in model_size.lower() or "7B" in model_size
    if is_7b:
        # 7B 4-bit ≈ 4GB model, grad_checkpoint 포함
        if mem_gb >= 32:
            return max(cfg_batch, 4)
        elif mem_gb >= 16:
            return max(cfg_batch, 2)
        else:
            return min(cfg_batch, 2)
    else:
        # 3B 4-bit ≈ 2GB model
        if mem_gb >= 32:
            return max(cfg_batch, 8)
        elif mem_gb >= 16:
            return max(cfg_batch, 6)
        else:
            return min(cfg_batch, 4)


# ── iters 동적 계산 ───────────────────────────────────────────────────────────

def _calc_iters(n_train: int, batch_size: int, epochs: int) -> int:
    steps_per_epoch = math.ceil(n_train / batch_size)
    return steps_per_epoch * epochs


# ── 학습 실행 (stdout 파싱 + early stopping) ──────────────────────────────────

class EarlyStopper:
    """
    Val loss patience 기반 early stopping.

    patience: val loss가 연속으로 개선되지 않는 횟수 허용 한도
    min_delta: 이 이상 감소해야 '개선'으로 인정
    """

    def __init__(self, patience: int = 5, min_delta: float = 1e-4) -> None:
        self.patience = patience
        self.min_delta = min_delta
        self.best_loss = float("inf")
        self.best_iter = 0
        self.no_improve = 0
        self.history: list[tuple[int, float]] = []   # (iter, val_loss)

    def update(self, iteration: int, val_loss: float) -> bool:
        """True 반환 시 학습 중단 (patience 초과)."""
        self.history.append((iteration, val_loss))
        if val_loss < self.best_loss - self.min_delta:
            self.best_loss = val_loss
            self.best_iter = iteration
            self.no_improve = 0
        else:
            self.no_improve += 1
        return self.no_improve >= self.patience


def _run_training(
    cmd: list[str],
    patience: int,
    total_iters: int,
) -> tuple[EarlyStopper, list[tuple[int, float]]]:
    """
    mlx-lm 서브프로세스 실행.
    stdout을 실시간으로 파싱해 val loss 추적 + early stopping.
    patience 초과 시 프로세스를 종료합니다.
    """
    stopper = EarlyStopper(patience=patience)
    train_history: list[tuple[int, float]] = []
    stopped_early = False

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    print(f"{'─'*60}")
    try:
        for line in proc.stdout:  # type: ignore[union-attr]
            print(line, end="", flush=True)

            # train loss 수집
            tm = _TRAIN_RE.search(line)
            if tm:
                train_history.append((int(tm.group(1)), float(tm.group(2))))

            # val loss 수집 + early stopping 판단
            vm = _VAL_RE.search(line)
            if vm:
                it = int(vm.group(1))
                vl = float(vm.group(2))
                should_stop = stopper.update(it, vl)
                if should_stop:
                    print(
                        f"\n[Early Stop] {patience}회 연속 val loss 미개선 "
                        f"(best={stopper.best_loss:.4f} @ iter {stopper.best_iter})"
                    )
                    proc.terminate()
                    stopped_early = True
                    break
    except KeyboardInterrupt:
        print("\n[중단] Ctrl+C — 현재 상태로 종료합니다.")
        proc.terminate()

    proc.wait()
    if not stopped_early and proc.returncode not in (0, -15):
        print(f"[오류] 학습 실패 (exit={proc.returncode})")
        sys.exit(proc.returncode)

    return stopper, train_history


# ── 최적 체크포인트 선택 ──────────────────────────────────────────────────────

def _select_best_checkpoint(
    adapter_dir: Path,
    stopper: EarlyStopper,
) -> Path | None:
    """
    val loss 히스토리에서 최적 iter를 찾아 해당 체크포인트를 best_adapters.npz로 복사.
    체크포인트 파일 형식: {iter:07d}_adapters.npz
    """
    if not stopper.history:
        return None

    best_iter = stopper.best_iter
    print(f"\n[Best Checkpoint] iter={best_iter}, val_loss={stopper.best_loss:.4f}")

    # 정확히 일치하는 체크포인트 탐색
    candidates = sorted(adapter_dir.glob("*_adapters.npz"))
    if not candidates:
        # 체크포인트 없으면 adapters.npz (마지막) 사용
        last = adapter_dir / "adapters.npz"
        if last.exists():
            print(f"  체크포인트 없음 — 최종 adapters.npz 사용")
            return last
        return None

    # best_iter에 가장 가까운 (≤) 체크포인트 선택
    best_ckpt = None
    for ckpt in candidates:
        m = re.match(r"(\d+)_adapters\.npz", ckpt.name)
        if m and int(m.group(1)) <= best_iter:
            best_ckpt = ckpt

    if best_ckpt is None:
        best_ckpt = candidates[0]

    dest = adapter_dir / "best_adapters.npz"
    shutil.copy2(best_ckpt, dest)
    print(f"  {best_ckpt.name} → best_adapters.npz")
    return dest


# ── val loss 곡선 텍스트 출력 ─────────────────────────────────────────────────

def _print_loss_curve(stopper: EarlyStopper, width: int = 50) -> None:
    history = stopper.history
    if len(history) < 2:
        return

    losses = [l for _, l in history]
    iters  = [i for i, _ in history]
    lo, hi = min(losses), max(losses)
    span = hi - lo or 1.0

    print(f"\n[Val Loss 곡선]  (best={stopper.best_loss:.4f} @ iter {stopper.best_iter})")
    print(f"  {'iter':>6}  {'val_loss':>9}  chart")
    print(f"  {'─'*6}  {'─'*9}  {'─'*width}")

    for it, vl in history:
        bar_len = int((hi - vl) / span * width)
        marker = "*" if it == stopper.best_iter else " "
        bar = "█" * bar_len
        print(f"  {it:6d}  {vl:9.4f} {marker} {bar}")

    print()


# ── 학습 후 요약 ──────────────────────────────────────────────────────────────

def _post_train_summary(
    adapter_dir: Path,
    stopper: EarlyStopper,
    elapsed: float,
    best_ckpt: Path | None,
) -> None:
    files = list(Path(adapter_dir).glob("*"))
    print(f"\n{'='*60}")
    print(f"학습 완료  ({elapsed/60:.1f}분)")
    print(f"  Best val loss : {stopper.best_loss:.4f}  @ iter {stopper.best_iter}")
    print(f"  Best adapter  : {best_ckpt or '(없음)'}")
    print(f"  체크포인트 수 : {len(list(Path(adapter_dir).glob('*_adapters.npz')))}")
    print(f"\n[저장된 파일 ({len(files)}개)]")
    for f in sorted(files):
        sz = f.stat().st_size // 1024
        print(f"  {f.name:35s}  {sz:6d} KB")

    best = f"{adapter_dir}/best_adapters.npz" if best_ckpt else adapter_dir
    print(f"\n다음 단계:")
    print(f"  평가:  python3 scripts/evaluate.py --adapter {adapter_dir}")
    print(f"  배포:  bash scripts/deploy_ollama.sh {adapter_dir}")
    print(f"{'='*60}")


# ── 메인 ─────────────────────────────────────────────────────────────────────

def run_training(
    config_path: str,
    epochs: int = 0,
    resume: bool = False,
    patience: int = 5,
    no_early_stop: bool = False,
) -> None:
    try:
        import yaml
    except ImportError:
        subprocess.run([sys.executable, "-m", "pip", "install", "pyyaml", "-q"])
        import yaml  # type: ignore[import]

    cfg_path = Path(config_path)
    if not cfg_path.exists():
        print(f"[오류] config 파일 없음: {cfg_path}")
        sys.exit(1)

    with cfg_path.open() as f:
        cfg: dict[str, Any] = yaml.safe_load(f)

    model_id: str    = cfg["model"]
    adapter_out: str = cfg.get("adapter_path", "lora-out/default")
    data_dir         = Path(cfg.get("data", "data"))

    print("=" * 60)
    print("S2N-Agent LoRA 학습")
    print(f"  모델    : {model_id}")
    print(f"  설정    : {cfg_path}")
    print(f"  Adapter : {adapter_out}")
    print(f"  데이터  : {data_dir}/")

    counts = _verify_data(data_dir)
    n_train = counts.get("train.jsonl", 0)

    # M1 메모리 감지 → batch_size 조정
    mem_gb = _get_memory_gb()
    if mem_gb > 0:
        print(f"  메모리  : {mem_gb:.0f} GB")
    cfg_batch = cfg.get("batch_size", 4)
    batch = _suggest_batch_size(cfg_batch, mem_gb, model_id)
    if batch != cfg_batch:
        print(f"  batch_size 조정: {cfg_batch} → {batch} (메모리 {mem_gb:.0f}GB 기준)")
        cfg["batch_size"] = batch

    # iters 동적 계산 (--epochs 지정 시)
    if epochs > 0:
        iters = _calc_iters(n_train, batch, epochs)
        steps_per_epoch = math.ceil(n_train / batch)
        print(f"  epochs  : {epochs}  ({steps_per_epoch} steps/epoch → {iters} iters)")
        cfg["iters"] = iters
        # LR schedule decay_steps도 iters에 맞춤
        if "lr_schedule" in cfg and isinstance(cfg["lr_schedule"], dict):
            args = cfg["lr_schedule"].get("arguments", [])
            if len(args) == 2:
                cfg["lr_schedule"]["arguments"] = [args[0], iters]
    else:
        iters = cfg.get("iters", 1600)
        print(f"  iters   : {iters}  (config 고정값)")

    print("=" * 60)

    # 수정된 config를 임시 파일에 저장
    tmp_cfg = cfg_path.parent / f"_tmp_{cfg_path.stem}.yaml"
    with tmp_cfg.open("w") as f:
        yaml.dump(cfg, f, default_flow_style=False, allow_unicode=True)

    # mlx-lm lora 커맨드 구성
    cmd = [sys.executable, "-m", "mlx_lm", "lora", "--config", str(tmp_cfg)]
    if resume:
        cmd += ["--resume-adapter-file", f"{adapter_out}/adapters.npz"]

    print(f"실행: {' '.join(cmd[:6])} ...\n")

    eff_patience = patience if not no_early_stop else 999_999
    start = time.time()
    stopper, _train_hist = _run_training(cmd, eff_patience, iters)
    elapsed = time.time() - start

    # 임시 config 삭제
    tmp_cfg.unlink(missing_ok=True)

    # val loss 곡선 출력
    _print_loss_curve(stopper)

    # 최적 체크포인트 선택
    best_ckpt = _select_best_checkpoint(Path(adapter_out), stopper)

    _post_train_summary(Path(adapter_out), stopper, elapsed, best_ckpt)


# ── 진입점 ────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="S2N-Agent LoRA 학습",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  python3 scripts/train.py --config configs/lora_3b.yaml --epochs 5
  python3 scripts/train.py --config configs/lora_7b.yaml --epochs 3 --patience 7
  python3 scripts/train.py --config configs/lora_3b.yaml --resume
  python3 scripts/train.py --config configs/lora_3b.yaml --no-early-stop
        """,
    )
    parser.add_argument("--config", default="configs/lora_3b.yaml")
    parser.add_argument(
        "--epochs", type=int, default=0,
        help="학습 epoch 수. 지정 시 config의 iters를 덮어씀 (권장)",
    )
    parser.add_argument(
        "--patience", type=int, default=5,
        help="Early stopping patience: val loss가 N회 연속 미개선 시 중단 (기본: 5)",
    )
    parser.add_argument(
        "--no-early-stop", action="store_true",
        help="Early stopping 비활성화 (config iters까지 전부 학습)",
    )
    parser.add_argument("--resume", action="store_true")
    parser.add_argument("--install-deps", action="store_true")
    args = parser.parse_args()

    if not _check_mlx():
        if args.install_deps:
            _install_mlx()
        else:
            print("[오류] mlx-lm 미설치:")
            print("  pip install mlx-lm")
            print("  또는: python3 scripts/train.py --config ... --install-deps")
            sys.exit(1)

    run_training(
        config_path=args.config,
        epochs=args.epochs,
        resume=args.resume,
        patience=args.patience,
        no_early_stop=args.no_early_stop,
    )
