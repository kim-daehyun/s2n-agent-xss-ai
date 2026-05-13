# 타 사용자 관점 검증 절차

이 문서는 배포 후 다른 사용자가 실제로 쓸 수 있는지 확인하기 위한 체크리스트입니다.

## 1. 새 디렉터리에서 clone

기존 작업 디렉터리가 아닌 새 위치에서 확인합니다.

```bash
cd /tmp
git clone https://github.com/kim-daehyun/s2n-agent-xss-ai.git
cd s2n-agent-xss-ai
```

## 2. Docker 이미지 빌드

```bash
docker compose build
```

확인:

```bash
docker compose config
```

`command`에 아래 옵션이 포함되어 있어야 합니다.

```text
--use-peft-agent
--adapter-path /app/adapters/xss-agent-qwen3b-clean-peft
```

## 3. Hugging Face adapter 다운로드

```bash
docker compose run --rm s2n-agent-report bash scripts/download_peft_adapter.sh
```

확인:

```bash
test -f adapters/xss-agent-qwen3b-clean-peft/adapter_config.json && \
test -f adapters/xss-agent-qwen3b-clean-peft/adapter_model.safetensors && \
test -f adapters/xss-agent-qwen3b-clean-peft/tokenizer.json && \
test -f adapters/xss-agent-qwen3b-clean-peft/tokenizer_config.json && \
echo "PEFT adapter OK"
```

## 4. DVWA smoke test

DVWA가 호스트 머신의 `4280` 포트에서 동작한다고 가정합니다.

```bash
docker compose run --rm s2n-agent-report \
  python -B scripts/plugin_agents/run_url_to_pdf.py \
  --url 'http://host.docker.internal:4280/vulnerabilities/xss_r/?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E' \
  --cookie 'PHPSESSID=replace-me; security=low' \
  --output-pdf /app/reports/generated/dvwa_peft_smoke.pdf \
  --reindex \
  --use-peft-agent \
  --adapter-path /app/adapters/xss-agent-qwen3b-clean-peft
```

성공 기준:

```bash
test -f reports/generated/dvwa_peft_smoke.pdf && echo "DVWA PDF OK"
```

PDF에서 `XSSAgent Judgement`, `Evidence`, `Official Reference Mapping` 섹션을 확인합니다.

## 5. Juice Shop smoke test

Juice Shop이 호스트 머신의 `3000` 포트에서 동작한다고 가정합니다.

```bash
docker compose run --rm s2n-agent-report \
  python -B scripts/plugin_agents/run_url_to_pdf.py \
  --url 'http://host.docker.internal:3000' \
  --output-pdf /app/reports/generated/juice_shop_peft_smoke.pdf \
  --reindex \
  --use-peft-agent \
  --adapter-path /app/adapters/xss-agent-qwen3b-clean-peft
```

성공 기준:

```bash
test -f reports/generated/juice_shop_peft_smoke.pdf && echo "Juice Shop PDF OK"
```

## 6. 로컬 XSS 테스트 페이지 smoke test

로컬 테스트 페이지가 호스트 머신의 `8080` 포트에서 동작한다고 가정합니다.

```bash
docker compose run --rm s2n-agent-report \
  python -B scripts/plugin_agents/run_url_to_pdf.py \
  --url 'http://host.docker.internal:8080/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E' \
  --output-pdf /app/reports/generated/local_xss_peft_smoke.pdf \
  --reindex \
  --use-peft-agent \
  --adapter-path /app/adapters/xss-agent-qwen3b-clean-peft
```

성공 기준:

```bash
test -f reports/generated/local_xss_peft_smoke.pdf && echo "Local XSS PDF OK"
```

## 7. 배포 전 Git 추적 확인

아래 명령이 아무것도 출력하지 않아야 합니다.

```bash
git ls-files | grep -E 'adapter_model\.safetensors|__pycache__|^storage/|^reports/generated/|^\.trash' || true
```

## 8. 실패 시 확인할 것

- Hugging Face repo `emmaemmaemma123/xss-agent-qwen3b-clean-peft`가 public인지 확인합니다.
- `adapters/xss-agent-qwen3b-clean-peft/`에 adapter 파일 4개가 있는지 확인합니다.
- CPU 환경에서는 PEFT inference가 오래 걸릴 수 있습니다.
- Docker에서 호스트 앱에 접근할 때는 `localhost`가 아니라 `host.docker.internal`을 사용합니다.
- DVWA는 `PHPSESSID`와 `security=low` 쿠키가 맞는지 확인합니다.
