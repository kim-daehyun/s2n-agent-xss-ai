#!/usr/bin/env bash
set -euo pipefail

ADAPTER_REPO="${ADAPTER_REPO:-emmaemmaemma123/xss-agent-qwen3b-clean-peft}"
ADAPTER_DIR="${ADAPTER_DIR:-adapters/xss-agent-qwen3b-clean-peft}"

echo "[PEFT] Hugging Face repo: ${ADAPTER_REPO}"
echo "[PEFT] Local adapter dir: ${ADAPTER_DIR}"

mkdir -p "${ADAPTER_DIR}"

if command -v huggingface-cli >/dev/null 2>&1; then
  huggingface-cli download "${ADAPTER_REPO}" \
    --local-dir "${ADAPTER_DIR}"
else
  python - <<'PY'
import os
from pathlib import Path

repo = os.environ.get("ADAPTER_REPO", "emmaemmaemma123/xss-agent-qwen3b-clean-peft")
target = Path(os.environ.get("ADAPTER_DIR", "adapters/xss-agent-qwen3b-clean-peft"))
target.mkdir(parents=True, exist_ok=True)

try:
    from huggingface_hub import snapshot_download
except ImportError as exc:
    raise SystemExit(
        "huggingface_hub is not installed. Install requirements-lock.txt, "
        "or run: python -m pip install huggingface_hub"
    ) from exc

try:
    snapshot_download(repo_id=repo, local_dir=str(target), local_dir_use_symlinks=False)
except TypeError:
    snapshot_download(repo_id=repo, local_dir=str(target))
PY
fi

missing=0
for file in adapter_config.json adapter_model.safetensors tokenizer.json tokenizer_config.json; do
  if [ ! -f "${ADAPTER_DIR}/${file}" ]; then
    echo "[PEFT][ERROR] missing: ${ADAPTER_DIR}/${file}" >&2
    missing=1
  fi
done

if [ "${missing}" -ne 0 ]; then
  exit 1
fi

echo "[OK] PEFT adapter is ready: ${ADAPTER_DIR}"
