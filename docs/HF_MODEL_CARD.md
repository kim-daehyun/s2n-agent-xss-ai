# xss-agent-qwen3b-clean-peft

이 저장소는 `s2n-agent-xss-ai` URL-to-PDF XSS 리포터에서 사용하는 PEFT adapter입니다.

## 기본 정보

- Adapter repo: `emmaemmaemma123/xss-agent-qwen3b-clean-peft`
- Base model: `Qwen/Qwen2.5-Coder-3B-Instruct`
- 사용 목적: 허가된 XSS 테스트 결과를 해석하고 PDF 리포트의 XSSAgent 판단 섹션을 보강
- 코드 repo: `https://github.com/kim-daehyun/s2n-agent-xss-ai`

## 파일 구성

```text
adapter_config.json
adapter_model.safetensors
tokenizer.json
tokenizer_config.json
chat_template.jinja
training_report.json
```

## 사용 방법

코드 repo를 clone한 뒤 adapter를 다운로드합니다.

```bash
git clone https://github.com/kim-daehyun/s2n-agent-xss-ai.git
cd s2n-agent-xss-ai
bash scripts/download_peft_adapter.sh
docker compose build
```

DVWA smoke test 예시:

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

## 안전 및 사용 제한

- 이 adapter와 코드 도구는 본인이 소유했거나 명시적으로 허가받은 테스트 대상에만 사용하세요.
- 공개 서비스로 노출하기 전에 SSRF 방어, private IP 차단, 요청 제한, 감사 로그를 추가해야 합니다.
- 생성된 PDF/JSON에는 대상 URL, payload, cookie 기반 세션 흔적이 포함될 수 있으므로 민감정보로 취급하세요.

## 알려진 한계

- DVWA reflected XSS와 Juice Shop 계열 DOM/search XSS 흐름을 중심으로 검증되었습니다.
- 모든 웹 애플리케이션, 모든 인증 흐름, 모든 XSS sink를 자동으로 탐지하지 않습니다.
- CPU 환경에서 inference가 느릴 수 있습니다.
- 공식 레퍼런스 매핑은 코드 repo의 curated catalog와 로컬 문서 RAG에 의존합니다.

## 라이선스

- Adapter 배포 라이선스: MIT
- Base model: `Qwen/Qwen2.5-Coder-3B-Instruct`의 라이선스와 사용 조건을 따릅니다.
