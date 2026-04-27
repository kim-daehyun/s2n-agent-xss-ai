# S2N-Agent

> **LLM-powered decision layer for the [S2N](https://github.com/504s2n/s2n) web vulnerability scanner**
>
> S2N 웹 취약점 스캐너를 위한 LLM 의사결정 레이어

---

## 개요 / Overview

**[한국어]**

S2N-Agent는 S2N 스캐너의 플러그인 선택·페이로드 계획·결과 해석을 LLM이 담당하도록 설계된 AI 레이어입니다.
기존 결정론적 스캔 파이프라인에 최소한의 변경으로 통합되며,
Qwen2.5-Coder 7B를 LoRA 파인튜닝하여 Ollama(로컬) 또는 HuggingFace(로컬 추론)로 실행합니다.

```
기존: URL/DOM → 조건 충족 → Plugin 실행
목표: URL/DOM/SiteMap/응답 → S2N-Agent 추론 → Plugin 선택 + Payload 계획 → 결과 해석
```

**[English]**

S2N-Agent is an AI layer that delegates plugin selection, payload planning, and result interpretation to a fine-tuned LLM.
It integrates with the existing S2N scanner pipeline with minimal changes and runs a LoRA-tuned Qwen2.5-Coder model via Ollama (local) or HuggingFace (local inference).

```
Before: URL/DOM → rule match → Plugin execution
After:  URL/DOM/SiteMap/response → S2N-Agent reasoning → Plugin selection + Payload plan → Result interpretation
```

---

## AI 모드 / AI Modes

| Mode         | 동작                                  | Behavior                          |
| ------------ | ------------------------------------- | --------------------------------- |
| `off`        | AI 없음, 기존 S2N 그대로              | Vanilla S2N, no AI                |
| `assist`     | AI 권고만 로그 출력, 실행은 기존 방식 | AI recommendations in log only    |
| `smart`      | AI가 플러그인 자동 선택               | AI selects plugins autonomously   |
| `aggressive` | AI 멀티스텝 공격 체인 계획            | AI plans multi-step attack chains |

---

## 설치 / Installation

### 요구사항 / Requirements

- Python 3.10+
- S2N `>= 0.3.2` (`pip install s2n`)
- [Ollama](https://ollama.ai) (로컬 추론 / local inference)

### S2N-Agent 설치 / Install

```bash
# 기본 설치 (Ollama 클라이언트만)
pip install s2n-agent

# HuggingFace 로컬 추론 포함
pip install "s2n-agent[huggingface]"

# LoRA 학습 환경 (Apple Silicon)
pip install "s2n-agent[train]"

# 개발 환경
pip install "s2n-agent[dev]"
```

---

## S2N 통합 / S2N Integration

S2N v1.0.0부터 `--ai-mode` 옵션이 내장됩니다.
S2N 스캐너를 최신 버전으로 업데이트하면 자동으로 사용 가능합니다.

S2N v1.0.0+ includes built-in `--ai-mode` support. Update S2N to the latest version to use it.

### CLI 사용법 / CLI Usage

```bash
# AI 없음 (기존 동작)
s2n scan -u https://target.com

# assist 모드 — AI 권고를 로그에 출력, 실행은 기존 플러그인
s2n scan -u https://target.com --ai-mode assist

# smart 모드 — AI가 최적 플러그인 자동 선택
s2n scan -u https://target.com --ai-mode smart

# aggressive 모드 — AI 멀티스텝 공격 계획
s2n scan -u https://target.com --ai-mode aggressive

# 모델/엔드포인트 지정
s2n scan -u https://target.com \
  --ai-mode smart \
  --ai-model s2n-agent \
  --ai-endpoint http://localhost:11434
```

### Python API

```python
from s2nagent import S2NAgent

agent = S2NAgent(
    endpoint="http://localhost:11434",
    model="s2n-agent",
    mode="smart",
)

# Task A — 플러그인 선택
result = agent.select_plugin(
    url="/search?q=test",
    dom="<input name='q' type='text'>",
    sitemap_summary="3 forms, 0 file inputs",
)
# {"plugin": "xss", "confidence": 91, "reason": "input[name=q] detected"}

# Task B — 페이로드 계획
payloads = agent.plan_payloads(plugin="xss", parameter="q", context="html_body")
# {"payloads": ["<svg/onload=alert(1)>", ...], "strategy": "..."}

# Task C — FP 필터
verdict = agent.filter_false_positive(
    finding="Possible XSS",
    evidence="<script>alert(1)</script>",
    response_body="<script>alert(1)</script> reflected",
)
# {"verdict": "confirmed", "confidence": 95, "reason": "..."}

# Task D — 다음 액션 계획
plan = agent.plan_next_action(
    completed=["xss", "csrf"],
    findings=[{"plugin": "jwt", "severity": "HIGH"}],
    sitemap="admin route /admin/panel discovered",
)
# {"next_action": "path_traversal", "priority": "high", "reason": "..."}

# on_finding 콜백 (Scanner 실시간 피드백)
from s2n.s2nscanner.scan_engine import Scanner
scanner = Scanner(config=config, on_finding=agent.analyze_finding)
```

---

## 모델 학습 / Model Training

### 1단계: 데이터 준비 / Step 1: Prepare Data

학습 데이터는 4개 태스크(A–D) JSONL 포맷으로 생성됩니다.
Training data is generated in 4-task (A–D) JSONL format.

```bash
# 4,000 샘플 생성 (기본값)
python3 -m s2nagent.data.generator --count 4000 --output data/train.jsonl

# 특정 태스크만 생성
python3 -m s2nagent.data.generator --task a --count 800 --output data/xss_select.jsonl

# train / valid / test 분리 (80 / 10 / 10)
python3 scripts/split_data.py
```

**데이터 통계 (기본 생성 기준):**

| 태스크                    | 내용                     | 샘플 수   |
| ------------------------- | ------------------------ | --------- |
| A — Plugin Selection      | URL/DOM → 플러그인 선택  | 1,200     |
| B — Payload Planning      | 플러그인 → 페이로드 목록 | 800       |
| C — False Positive Filter | Finding → FP 판별        | 1,200     |
| D — Multi-step Planner    | 진행 상황 → 다음 액션    | 800       |
| **합계**                  |                          | **4,000** |

### 2단계: LoRA 학습 / Step 2: LoRA Training

mlx-lm (Apple Silicon)을 사용한 LoRA 파인튜닝.
LoRA fine-tuning with mlx-lm (Apple Silicon).

```bash
# mlx-lm 설치
pip install mlx-lm

# 3B 실험용 학습 (~20–30분 / M3 기준)
python3 scripts/train.py --config configs/lora_3b.yaml

# 7B 실전용 학습 (~60–90분 / M3 기준)
python3 scripts/train.py --config configs/lora_7b.yaml

# 중단 후 재개
python3 scripts/train.py --config configs/lora_3b.yaml --resume

# mlx-lm 직접 실행
mlx_lm.lora --config configs/lora_3b.yaml
```

**모델 권장 사양:**

| 모델                  | VRAM  | 용도        |
| --------------------- | ----- | ----------- |
| Qwen2.5-Coder-3B-4bit | ~4 GB | 빠른 실험   |
| Qwen2.5-Coder-7B-4bit | ~8 GB | 실전 (권장) |

### 3단계: 평가 / Step 3: Evaluation

```bash
# LoRA adapter 직접 평가
python3 scripts/evaluate.py \
  --adapter lora-out/3b \
  --model mlx-community/Qwen2.5-Coder-3B-Instruct-4bit

# 배포된 Ollama 모델 평가
python3 scripts/evaluate.py \
  --adapter ollama \
  --model s2n-agent

# 빠른 확인 (100 샘플)
python3 scripts/evaluate.py --adapter ollama --max-samples 100
```

**목표 지표 / Target Metrics:**

| 지표                  | 목표 | Metric                    | Target |
| --------------------- | ---- | ------------------------- | ------ |
| Plugin 선택 정확도    | 85%+ | Plugin selection accuracy | 85%+   |
| False Positive 감소율 | 30%+ | FP reduction rate         | 30%+   |
| JSON 파싱 성공률      | 95%+ | JSON parse success rate   | 95%+   |

---

## 배포 파이프라인 / Deployment Pipeline

### Ollama 배포 (권장) / Ollama Deployment (Recommended)

```bash
# 1. Ollama 설치 — https://ollama.ai

# 2. base 모델 다운로드
ollama pull qwen2.5-coder:7b

# 3. LoRA adapter fuse + 모델 등록 (한 번에 자동화)
bash scripts/deploy_ollama.sh lora-out/3b    # 3B
bash scripts/deploy_ollama.sh lora-out/7b    # 7B

# 4. 동작 확인
ollama run s2n-agent '{"url":"/search?q=test","dom":"<input name=q>","sitemap_summary":"1 form"}'
```

**수동 단계 / Manual steps:**

```bash
# adapter fuse (MLX weights → 단일 모델)
python3 -m mlx_lm.fuse \
  --model mlx-community/Qwen2.5-Coder-7B-Instruct-4bit \
  --adapter-path lora-out/7b \
  --save-path s2n-fused

# Modelfile의 ADAPTER 라인 활성화
# (s2nagent/models/Modelfile 편집 후)
ollama create s2n-agent -f s2nagent/models/Modelfile
```

### HuggingFace 배포 / HuggingFace Deployment

```python
from s2nagent.client.huggingface import HuggingFaceClient

client = HuggingFaceClient(
    repo_id="your-org/s2n-agent-7b",   # HF Hub에 업로드된 모델
    load_in_4bit=True,                  # QLoRA 4-bit
)
result = client.generate(prompt, system=system_prompt)
```

---

## 프로젝트 구조 / Project Structure

```
s2n-agent/
├── s2nagent/
│   ├── agent.py                  # S2NAgent — 최상위 오케스트레이터
│   ├── client/
│   │   ├── ollama.py             # Ollama /api/generate 클라이언트
│   │   └── huggingface.py        # HuggingFace 로컬 추론 (MPS/CUDA/CPU)
│   ├── plugins/
│   │   └── s2n_agent_plugin.py   # S2NAgentPlugin (pre/run/post_scan/cleanup)
│   ├── tasks/
│   │   ├── plugin_selection.py   # Task A
│   │   ├── payload_planning.py   # Task B
│   │   ├── false_positive.py     # Task C
│   │   └── multi_step.py         # Task D
│   ├── data/
│   │   ├── generator.py          # 학습 데이터 생성기
│   │   └── schemas.py            # ChatML 스키마
│   └── models/
│       └── Modelfile             # Ollama 배포 설정
├── configs/
│   ├── lora_3b.yaml              # Qwen2.5-Coder-3B LoRA 설정
│   └── lora_7b.yaml              # Qwen2.5-Coder-7B LoRA 설정
├── data/
│   ├── train.jsonl               # 학습 데이터 (3,200 samples)
│   ├── valid.jsonl               # 검증 데이터 (400 samples)
│   └── test.jsonl                # 테스트 데이터 (400 samples)
├── scripts/
│   ├── split_data.py             # train/val/test 분리
│   ├── train.py                  # mlx-lm 학습 래퍼
│   ├── evaluate.py               # 평가 스크립트
│   └── deploy_ollama.sh          # Ollama 배포 자동화
└── pyproject.toml
```

---

## S2N 통합 상세 / S2N Integration Details

S2N 스캐너의 플러그인 생명주기 훅을 활용합니다.
Hooks into S2N scanner's plugin lifecycle.

```
Scanner.scan()
  ↓ smart_crawl() → scan_context.sitemap 자동 첨부
  ↓ for plugin in discovered_plugins:
      ↓ plugin.pre_scan(ctx)   ← AI: sitemap 분석, 실행 여부 결정
      ↓ plugin.run(ctx)        ← 실제 스캔
      ↓ plugin.post_scan(ctx)  ← AI: 결과 해석, 다음 액션 계획
      ↓ plugin.cleanup(ctx)
  ↓ ScanReport 반환
```

**수동 통합 / Manual integration (without CLI):**

```python
from s2n.s2nscanner.scan_engine import Scanner
from s2n.s2nscanner.interfaces import ScanConfig, ScannerConfig
from s2nagent.plugins.s2n_agent_plugin import S2NAgentPlugin

agent_plugin = S2NAgentPlugin(
    ai_mode="smart",
    ai_model="s2n-agent",
    ai_endpoint="http://localhost:11434",
)

scanner = Scanner(
    config=ScanConfig(
        target_url="https://target.com",
        scanner_config=ScannerConfig(ai_mode="smart"),
    ),
    plugins=[agent_plugin],
    on_finding=lambda f: print(f"Finding: {f.title}"),
)
report = scanner.scan()
```

---

## MITRE ATT&CK 매핑 / MITRE ATT&CK Mapping

S2N-Agent가 선택할 수 있는 플러그인과 ATT&CK 매핑.
Plugins available for AI selection and their ATT&CK mappings.

| Plugin             | TID       | Tactic            |
| ------------------ | --------- | ----------------- |
| `xss`              | T1059.007 | Execution         |
| `sqlinjection`     | T1190     | Initial Access    |
| `oscommand`        | T1059     | Execution         |
| `csrf`             | T1185     | Collection        |
| `file_upload`      | T1505.003 | Persistence       |
| `brute_force`      | T1110     | Credential Access |
| `soft_brute_force` | T1110     | Credential Access |
| `jwt`              | T1528     | Credential Access |
| `autobot`          | T1190     | Initial Access    |
| `path_traversal`   | T1083     | Discovery         |
| `sensitive_files`  | T1552.001 | Credential Access |
| `react2shell`      | T1505.003 | Persistence       |

---

## 개발 로드맵 / Development Roadmap

| 주차   | 상태         | 작업                                                                                           |
| ------ | ------------ | ---------------------------------------------------------------------------------------------- |
| Week 1 | ✅ 완료      | ScannerConfig AI 필드, CLI 옵션, 패키지 구조, Ollama/HF 클라이언트, Tasks A-D, 4,000 샘플 생성 |
| Week 2 | ✅ 완료      | train/val/test 분리, LoRA 설정(3B/7B), 학습 스크립트, 평가 스크립트, Ollama 배포 자동화        |
| Week 3 | 🔄 진행 예정 | Payload Planner 고도화, `on_finding` 실시간 피드백 연결                                        |
| Week 4 | ⏳ 예정      | Ollama 실전 배포, CLI `--ai-mode` 공개, 벤치마크                                               |

---

## 라이선스 / License

MIT License. See [LICENSE](LICENSE).

---

> **주의**: 이 도구는 허가된 보안 테스트 및 교육 목적으로만 사용하세요.
> **Warning**: This tool is intended for authorized security testing and educational purposes only.
