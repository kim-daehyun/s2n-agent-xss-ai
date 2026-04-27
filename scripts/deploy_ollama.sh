#!/usr/bin/env bash
# S2N-Agent Ollama 배포 스크립트
#
# 사용법:
#   bash scripts/deploy_ollama.sh lora-out/3b    # 3B adapter 배포
#   bash scripts/deploy_ollama.sh lora-out/7b    # 7B adapter 배포
#   bash scripts/deploy_ollama.sh none           # base 모델만 (adapter 없이)
#
# 전제 조건:
#   - Ollama 설치 (https://ollama.ai)
#   - mlx-lm 설치 (pip install mlx-lm)
#   - adapter 학습 완료 (python3 scripts/train.py)

set -euo pipefail

ADAPTER_PATH="${1:-lora-out/3b}"
MODEL_NAME="s2n-agent"
MODELFILE="s2nagent/models/Modelfile"
FUSED_DIR="s2n-fused"

# ── 색상 출력 ─────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; exit 1; }

# ── 사전 검사 ─────────────────────────────────────────────────────────────────
command -v ollama >/dev/null 2>&1 || error "Ollama 미설치. https://ollama.ai 에서 설치 후 재실행"

info "배포 시작: adapter=${ADAPTER_PATH}, model=${MODEL_NAME}"

# ── Step 1: adapter 존재 확인 ─────────────────────────────────────────────────
if [ "${ADAPTER_PATH}" != "none" ]; then
    if [ ! -d "${ADAPTER_PATH}" ]; then
        error "Adapter 디렉토리 없음: ${ADAPTER_PATH}\n  먼저 학습 실행: python3 scripts/train.py --config configs/lora_3b.yaml"
    fi

    ADAPTER_FILE="${ADAPTER_PATH}/adapters.npz"
    if [ ! -f "${ADAPTER_FILE}" ]; then
        # 마지막 체크포인트 탐색
        ADAPTER_FILE=$(ls -t "${ADAPTER_PATH}"/*.npz 2>/dev/null | head -1 || true)
        if [ -z "${ADAPTER_FILE}" ]; then
            error "adapter 파일(.npz) 없음: ${ADAPTER_PATH}"
        fi
        warn "adapters.npz 없음 — 마지막 체크포인트 사용: ${ADAPTER_FILE}"
    fi

    info "Adapter: ${ADAPTER_FILE}"

    # ── Step 2: LoRA fuse (adapter → 단일 모델 가중치) ───────────────────────
    # config에서 base 모델 추출
    CONFIG_FILE=""
    if [ -f "configs/lora_3b.yaml" ] && echo "${ADAPTER_PATH}" | grep -q "3b"; then
        CONFIG_FILE="configs/lora_3b.yaml"
    elif [ -f "configs/lora_7b.yaml" ] && echo "${ADAPTER_PATH}" | grep -q "7b"; then
        CONFIG_FILE="configs/lora_7b.yaml"
    fi

    if [ -n "${CONFIG_FILE}" ]; then
        BASE_MODEL=$(python3 -c "import yaml; c=yaml.safe_load(open('${CONFIG_FILE}')); print(c['model'])")
    else
        # 기본값
        BASE_MODEL="mlx-community/Qwen2.5-Coder-3B-Instruct-4bit"
        warn "config 파일 미확인 — base 모델 기본값 사용: ${BASE_MODEL}"
    fi

    info "Base 모델: ${BASE_MODEL}"
    info "LoRA fuse 시작 → ${FUSED_DIR}/"

    python3 -m mlx_lm.fuse \
        --model "${BASE_MODEL}" \
        --adapter-path "${ADAPTER_PATH}" \
        --save-path "${FUSED_DIR}" \
        --de-quantize

    info "Fuse 완료: ${FUSED_DIR}/"

    # Modelfile의 ADAPTER 라인 활성화
    sed -i.bak \
        "s|^# ADAPTER.*|ADAPTER ./${FUSED_DIR}|" \
        "${MODELFILE}"
    info "Modelfile ADAPTER 활성화"
else
    info "adapter=none — base 모델로 배포"
    # Modelfile의 ADAPTER 라인 비활성화 (주석 처리)
    sed -i.bak \
        "s|^ADAPTER.*|# ADAPTER (not set)|" \
        "${MODELFILE}"
fi

# ── Step 3: Ollama 모델 생성 ──────────────────────────────────────────────────
info "ollama create ${MODEL_NAME} ..."
ollama create "${MODEL_NAME}" -f "${MODELFILE}"

# ── Step 4: 기본 동작 확인 ────────────────────────────────────────────────────
info "배포 확인 중..."
TEST_PROMPT='{"url": "/search?q=test", "dom": "<input name=q>", "sitemap_summary": "1 form"}'

RESPONSE=$(ollama run "${MODEL_NAME}" "${TEST_PROMPT}" 2>&1 | head -5)
echo "  응답: ${RESPONSE}"

# JSON 파싱 가능 여부 확인
python3 -c "
import json, sys
try:
    data = json.loads('''${RESPONSE}''')
    plugin = data.get('plugin', '?')
    conf   = data.get('confidence', '?')
    print(f'  JSON OK — plugin={plugin}, confidence={conf}')
except:
    print('  경고: JSON 파싱 실패 (모델 출력 확인 필요)')
" 2>/dev/null || warn "응답 파싱 스킵"

info "배포 완료!"
echo ""
echo "사용법:"
echo "  s2n scan -u https://target.com --ai-mode smart --ai-model ${MODEL_NAME}"
echo "  ollama run ${MODEL_NAME} '{\"url\":\"/search\",\"dom\":\"<input name=q>\"}'"
