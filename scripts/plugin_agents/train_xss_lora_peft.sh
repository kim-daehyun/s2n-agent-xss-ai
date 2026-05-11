#!/usr/bin/env bash
set -euo pipefail

BASE_MODEL="${BASE_MODEL:-meta-llama/Meta-Llama-3.1-8B-Instruct}"
TRAIN_FILE="${TRAIN_FILE:-data/plugin_agents/xss_peft/train.jsonl}"
VALID_FILE="${VALID_FILE:-data/plugin_agents/xss_peft/valid.jsonl}"
OUTPUT_DIR="${OUTPUT_DIR:-adapters/xss-agent-8b-peft}"

MAX_LENGTH="${MAX_LENGTH:-768}"
EPOCHS="${EPOCHS:-1}"
BATCH_SIZE="${BATCH_SIZE:-1}"
GRAD_ACCUM_STEPS="${GRAD_ACCUM_STEPS:-8}"
LEARNING_RATE="${LEARNING_RATE:-0.00002}"
WARMUP_STEPS="${WARMUP_STEPS:-10}"
EVAL_EVERY="${EVAL_EVERY:-50}"
SAVE_EVERY="${SAVE_EVERY:-100}"

TRAIN_LOG="${TRAIN_LOG:-reports/xss_agent/xss_lora_peft_train.log}"

mkdir -p "$(dirname "${TRAIN_LOG}")"

echo "================================================================================"
echo "XSSAgent PEFT LoRA fine-tuning"
echo "================================================================================"
echo "BASE_MODEL=${BASE_MODEL}"
echo "TRAIN_FILE=${TRAIN_FILE}"
echo "VALID_FILE=${VALID_FILE}"
echo "OUTPUT_DIR=${OUTPUT_DIR}"
echo "MAX_LENGTH=${MAX_LENGTH}"
echo "EPOCHS=${EPOCHS}"
echo "BATCH_SIZE=${BATCH_SIZE}"
echo "GRAD_ACCUM_STEPS=${GRAD_ACCUM_STEPS}"
echo "LEARNING_RATE=${LEARNING_RATE}"
echo "TRAIN_LOG=${TRAIN_LOG}"
echo "================================================================================"

python scripts/plugin_agents/train_xss_lora_peft.py \
  --base-model "${BASE_MODEL}" \
  --train-file "${TRAIN_FILE}" \
  --valid-file "${VALID_FILE}" \
  --output-dir "${OUTPUT_DIR}" \
  --max-length "${MAX_LENGTH}" \
  --epochs "${EPOCHS}" \
  --batch-size "${BATCH_SIZE}" \
  --grad-accum-steps "${GRAD_ACCUM_STEPS}" \
  --learning-rate "${LEARNING_RATE}" \
  --warmup-steps "${WARMUP_STEPS}" \
  --eval-every "${EVAL_EVERY}" \
  --save-every "${SAVE_EVERY}" \
  2>&1 | tee "${TRAIN_LOG}"
