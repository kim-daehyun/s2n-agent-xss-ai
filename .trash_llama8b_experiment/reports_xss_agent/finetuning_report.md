# XSSAgent Fine-tuning Report

## 1. 목적

이번 실험의 목적은 XSSAgent의 baseline 모델과 LoRA fine-tuned 모델을 동일한 평가 조건에서 비교하는 것이다.

비교 기준은 아래와 같다.

- Baseline model: `s2n-agent-xss`
- Fine-tuned model: `s2n-agent-xss-ft`
- Runtime: Ollama
- Evaluation script: `scripts/plugin_agents/evaluate_xss_agent.py`
- Test set: `data/plugin_agents/xss/test.jsonl`

## 2. 데이터셋

최신 `main` 기준의 XSSAgent 평가 데이터셋 생성기를 사용했다.

생성 기준:

- total: 1000
- train: 800
- valid: 100
- test: 100
- seed: 42

Test set task 구성:

- selection: 30
- payload_planning: 25
- false_positive: 30
- next_action: 15

## 3. Baseline 평가

Baseline은 기존 Ollama 모델 `s2n-agent-xss`를 사용한다.

```bash
S2N_AGENT_XSS_MODEL=s2n-agent-xss \
PYTHONPATH=. python scripts/plugin_agents/evaluate_xss_agent.py \
  --test data/plugin_agents/xss/test.jsonl \
  --out reports/xss_agent/baseline_eval_rerun.json \
  --details-out reports/xss_agent/baseline_eval_rerun_details.json \
  --progress-every 10
```