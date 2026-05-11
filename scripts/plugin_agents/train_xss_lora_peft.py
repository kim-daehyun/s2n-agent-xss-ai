from __future__ import annotations

import argparse
import json
import math
import os
import random
from pathlib import Path
from typing import Any

import torch
from peft import LoraConfig, TaskType, get_peft_model
from torch.utils.data import DataLoader
from transformers import AutoModelForCausalLM, AutoTokenizer, get_linear_schedule_with_warmup


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Train XSSAgent LoRA adapter with PEFT.")

    parser.add_argument("--base-model", required=True)
    parser.add_argument("--train-file", required=True)
    parser.add_argument("--valid-file", required=True)
    parser.add_argument("--output-dir", required=True)

    parser.add_argument("--max-length", type=int, default=384)
    parser.add_argument("--epochs", type=int, default=1)
    parser.add_argument("--batch-size", type=int, default=1)
    parser.add_argument("--grad-accum-steps", type=int, default=8)
    parser.add_argument("--learning-rate", type=float, default=2e-5)
    parser.add_argument("--warmup-steps", type=int, default=10)

    parser.add_argument("--eval-every", type=int, default=100)
    parser.add_argument("--save-every", type=int, default=100)

    parser.add_argument("--max-train-records", type=int, default=None)
    parser.add_argument("--max-valid-records", type=int, default=None)

    parser.add_argument(
        "--skip-final-eval",
        action="store_true",
        help="Skip final evaluation. Recommended on Apple MPS to avoid mps_matmul shape errors.",
    )

    parser.add_argument(
        "--disable-eval",
        action="store_true",
        help="Disable all evaluation during training.",
    )

    return parser.parse_args()


def set_seed(seed: int = 42) -> None:
    random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)


def read_jsonl(path: str | Path, limit: int | None = None) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []

    with Path(path).open("r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue

            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON at {path}:{line_no}: {exc}") from exc

            if limit is not None and len(records) >= limit:
                break

    return records


def chatml_to_text(record: dict[str, Any], tokenizer: Any) -> str:
    messages = record.get("messages", [])

    if hasattr(tokenizer, "apply_chat_template") and tokenizer.chat_template:
        return tokenizer.apply_chat_template(
            messages,
            tokenize=False,
            add_generation_prompt=False,
        )

    parts: list[str] = []
    for message in messages:
        role = message.get("role", "")
        content = message.get("content", "")
        parts.append(f"<|{role}|>\n{content}")

    return "\n".join(parts)


def encode_records(
    *,
    records: list[dict[str, Any]],
    tokenizer: Any,
    max_length: int,
) -> list[dict[str, torch.Tensor]]:
    encoded: list[dict[str, torch.Tensor]] = []

    for record in records:
        text = chatml_to_text(record, tokenizer)

        item = tokenizer(
            text,
            truncation=True,
            max_length=max_length,
            padding="max_length",
            return_tensors="pt",
        )

        input_ids = item["input_ids"][0]
        attention_mask = item["attention_mask"][0]

        labels = input_ids.clone()
        labels[attention_mask == 0] = -100

        encoded.append(
            {
                "input_ids": input_ids,
                "attention_mask": attention_mask,
                "labels": labels,
            }
        )

    return encoded


def collate_batch(batch: list[dict[str, torch.Tensor]]) -> dict[str, torch.Tensor]:
    return {
        "input_ids": torch.stack([item["input_ids"] for item in batch]),
        "attention_mask": torch.stack([item["attention_mask"] for item in batch]),
        "labels": torch.stack([item["labels"] for item in batch]),
    }


def get_device() -> torch.device:
    if torch.backends.mps.is_available():
        return torch.device("mps")

    if torch.cuda.is_available():
        return torch.device("cuda")

    return torch.device("cpu")


def save_adapter(model: Any, tokenizer: Any, output_dir: str | Path) -> None:
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    model.save_pretrained(output_path)
    tokenizer.save_pretrained(output_path)


def save_checkpoint(model: Any, tokenizer: Any, output_dir: str | Path, step: int) -> Path:
    checkpoint_dir = Path(output_dir) / f"checkpoint-{step:04d}"
    checkpoint_dir.mkdir(parents=True, exist_ok=True)

    model.save_pretrained(checkpoint_dir)
    tokenizer.save_pretrained(checkpoint_dir)

    return checkpoint_dir


@torch.no_grad()
def evaluate(
    *,
    model: Any,
    dataloader: DataLoader,
    device: torch.device,
) -> float:
    model.eval()

    losses: list[float] = []

    for batch in dataloader:
        batch = {key: value.to(device) for key, value in batch.items()}
        outputs = model(**batch)
        losses.append(float(outputs.loss.detach().cpu()))

    model.train()

    if not losses:
        return float("nan")

    return sum(losses) / len(losses)


def main() -> None:
    args = parse_args()
    set_seed(42)

    print("=" * 80)
    print("XSSAgent PEFT LoRA fine-tuning")
    print("=" * 80)
    print(f"base_model={args.base_model}")
    print(f"train_file={args.train_file}")
    print(f"valid_file={args.valid_file}")
    print(f"output_dir={args.output_dir}")
    print(f"max_length={args.max_length}")
    print(f"epochs={args.epochs}")
    print(f"batch_size={args.batch_size}")
    print(f"grad_accum_steps={args.grad_accum_steps}")
    print(f"learning_rate={args.learning_rate}")
    print(f"warmup_steps={args.warmup_steps}")
    print(f"eval_every={args.eval_every}")
    print(f"save_every={args.save_every}")
    print(f"max_train_records={args.max_train_records}")
    print(f"max_valid_records={args.max_valid_records}")
    print(f"skip_final_eval={args.skip_final_eval}")
    print(f"disable_eval={args.disable_eval}")
    print("=" * 80)

    device = get_device()
    print(f"device={device}")

    print("Loading tokenizer...")
    tokenizer = AutoTokenizer.from_pretrained(
        args.base_model,
        trust_remote_code=True,
    )

    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    print("Loading base model...")

    # MPS에서는 float16/bfloat16 조합이 특정 matmul에서 터질 수 있으므로
    # 우선 float32로 둔다. 속도는 느려질 수 있지만 안정성이 더 중요하다.
    if device.type == "mps":
        dtype = torch.float32
        model = AutoModelForCausalLM.from_pretrained(
            args.base_model,
            torch_dtype=dtype,
            trust_remote_code=True,
        )
        model.to(device)
    elif device.type == "cuda":
        dtype = torch.float16
        model = AutoModelForCausalLM.from_pretrained(
            args.base_model,
            torch_dtype=dtype,
            device_map="auto",
            trust_remote_code=True,
        )
    else:
        dtype = torch.float32
        model = AutoModelForCausalLM.from_pretrained(
            args.base_model,
            torch_dtype=dtype,
            trust_remote_code=True,
        )
        model.to(device)

    lora_config = LoraConfig(
        task_type=TaskType.CAUSAL_LM,
        r=16,
        lora_alpha=32,
        lora_dropout=0.05,
        target_modules=[
            "q_proj",
            "k_proj",
            "v_proj",
            "o_proj",
            "gate_proj",
            "up_proj",
            "down_proj",
        ],
        bias="none",
    )

    model = get_peft_model(model, lora_config)
    model.train()

    trainable_params = sum(param.numel() for param in model.parameters() if param.requires_grad)
    total_params = sum(param.numel() for param in model.parameters())
    print(
        f"trainable params: {trainable_params:,} || "
        f"all params: {total_params:,} || "
        f"trainable%: {trainable_params / total_params:.4f}"
    )

    train_records = read_jsonl(args.train_file, args.max_train_records)
    valid_records = read_jsonl(args.valid_file, args.max_valid_records)

    print(f"train_records={len(train_records)}")
    print(f"valid_records={len(valid_records)}")

    train_dataset = encode_records(
        records=train_records,
        tokenizer=tokenizer,
        max_length=args.max_length,
    )

    valid_dataset = encode_records(
        records=valid_records,
        tokenizer=tokenizer,
        max_length=args.max_length,
    )

    train_loader = DataLoader(
        train_dataset,
        batch_size=args.batch_size,
        shuffle=True,
        collate_fn=collate_batch,
    )

    valid_loader = DataLoader(
        valid_dataset,
        batch_size=1,
        shuffle=False,
        collate_fn=collate_batch,
    )

    total_update_steps = math.ceil(len(train_loader) * args.epochs / args.grad_accum_steps)
    total_update_steps = max(total_update_steps, 1)

    print(f"total_update_steps={total_update_steps}")
    print("Starting training...")

    optimizer = torch.optim.AdamW(
        [param for param in model.parameters() if param.requires_grad],
        lr=args.learning_rate,
    )

    scheduler = get_linear_schedule_with_warmup(
        optimizer,
        num_warmup_steps=min(args.warmup_steps, total_update_steps),
        num_training_steps=total_update_steps,
    )

    global_step = 0
    micro_step = 0

    optimizer.zero_grad(set_to_none=True)

    for epoch in range(1, args.epochs + 1):
        for batch in train_loader:
            micro_step += 1

            batch = {key: value.to(device) for key, value in batch.items()}

            outputs = model(**batch)
            loss = outputs.loss / args.grad_accum_steps
            loss.backward()

            should_update = micro_step % args.grad_accum_steps == 0

            if should_update:
                optimizer.step()
                scheduler.step()
                optimizer.zero_grad(set_to_none=True)

                global_step += 1
                current_lr = scheduler.get_last_lr()[0]

                print(
                    f"step={global_step}/{total_update_steps} "
                    f"epoch={epoch} "
                    f"loss={float(loss.detach().cpu()) * args.grad_accum_steps:.4f} "
                    f"lr={current_lr:.6g}"
                )

                if args.save_every > 0 and global_step % args.save_every == 0:
                    checkpoint_dir = save_checkpoint(
                        model=model,
                        tokenizer=tokenizer,
                        output_dir=args.output_dir,
                        step=global_step,
                    )
                    print(f"saved checkpoint to {checkpoint_dir}")

                do_mid_eval = (
                    not args.disable_eval
                    and args.eval_every > 0
                    and global_step % args.eval_every == 0
                )

                if do_mid_eval:
                    try:
                        eval_loss = evaluate(
                            model=model,
                            dataloader=valid_loader,
                            device=device,
                        )
                        print(f"step={global_step} val_loss={eval_loss:.4f}")
                    except Exception as exc:
                        print(f"[WARN] mid evaluation failed: {type(exc).__name__}: {exc}")
                        print("[WARN] continuing training without stopping.")

            if global_step >= total_update_steps:
                break

        if global_step >= total_update_steps:
            break

    print("Training loop finished.")
    print("Saving final LoRA adapter before final evaluation...")

    save_adapter(
        model=model,
        tokenizer=tokenizer,
        output_dir=args.output_dir,
    )

    print(f"saved final adapter to {args.output_dir}")

    final_eval_loss: float | None = None

    if args.skip_final_eval or args.disable_eval:
        print("Skipping final evaluation.")
    else:
        try:
            print("Running final evaluation...")
            final_eval_loss = evaluate(
                model=model,
                dataloader=valid_loader,
                device=device,
            )
            print(f"final_val_loss={final_eval_loss:.4f}")
        except Exception as exc:
            print(f"[WARN] final evaluation failed: {type(exc).__name__}: {exc}")
            print("[WARN] adapter is already saved, so training output is preserved.")

    report = {
        "base_model": args.base_model,
        "train_file": args.train_file,
        "valid_file": args.valid_file,
        "output_dir": args.output_dir,
        "train_records": len(train_records),
        "valid_records": len(valid_records),
        "epochs": args.epochs,
        "batch_size": args.batch_size,
        "grad_accum_steps": args.grad_accum_steps,
        "learning_rate": args.learning_rate,
        "max_length": args.max_length,
        "global_step": global_step,
        "final_eval_loss": final_eval_loss,
        "device": str(device),
    }

    report_path = Path(args.output_dir) / "training_report.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    print("=" * 80)
    print("PEFT LoRA training finished")
    print(f"adapter_dir={args.output_dir}")
    print(f"report={report_path}")
    print("=" * 80)


if __name__ == "__main__":
    main()