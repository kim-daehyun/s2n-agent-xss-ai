# S2N Agent URL-to-PDF XSS 리포터

이 프로젝트는 **허가된 XSS 테스트 대상 URL을 입력하면 PDF 보안 리포트를 생성하는 로컬 Docker 도구**입니다.

현재 배포 기준의 핵심 흐름은 아래와 같습니다.

```text
URL 입력
-> XSS 반사/DOM 실행 여부 확인
-> Finding 정규화
-> 로컬 보안 가이드 RAG 검색
-> 공식 레퍼런스 매핑
-> PDF 리포트 생성
```

가장 중요한 실행 파일은 다음 하나입니다.

```bash
python -B scripts/plugin_agents/run_url_to_pdf.py
```

> 주의: 이 도구는 반드시 본인이 소유했거나 명시적으로 허가받은 대상에만 사용해야 합니다.

## 현재 버전에서 확인한 대상

현재 이 프로젝트는 다음 유형의 테스트를 목표로 정리되어 있습니다.

- DVWA reflected XSS URL
- DVWA처럼 쿠키가 필요한 실습 환경
- OWASP Juice Shop 검색/DOM 기반 XSS 흐름
- XSS finding을 PDF로 생성하는 URL-to-PDF 파이프라인

작성자가 로컬에서 URL-to-PDF 동작을 확인한 뒤 배포 정리를 진행한 상태입니다. 다만 이 README를 clone한 사용자는 자신의 환경에서 아래의 Docker 테스트 명령을 다시 실행해 최종 확인하는 것을 권장합니다.

## 지금 구조에서 FastAPI와 PEFT는 어떻게 쓰이나?

현재 `run_url_to_pdf.py`의 기본 실행은 **FastAPI 서버가 없어도 동작**합니다.

기본 모드:

- HTTP 요청 또는 Playwright 브라우저 probe로 XSS 신호를 확인합니다.
- rule-based finding을 생성합니다.
- PEFT XSSAgent 판단을 finding에 붙입니다.
- normalizer/RAG/PDF 파이프라인으로 리포트를 만듭니다.
- FastAPI 서버는 필요하지 않습니다.

PEFT 사용 정책:

- 이 배포판은 `--use-peft-agent`가 기본값입니다.
- Docker Compose 기본 command도 PEFT adapter를 사용하도록 고정되어 있습니다.
- adapter 파일이 없거나 모델 로딩에 실패하면 기본적으로 실패합니다.
- 정말로 rule-based 경로만 확인해야 할 때만 `--no-peft-agent`를 명시하세요.
- PEFT 실패 시에도 리포트를 계속 만들고 싶다면 `--allow-peft-fallback`을 명시하세요.

FastAPI 서버:

- `serving/xss_agent_server.py`에 별도로 존재합니다.
- `s2n_ai/fastapi_client.py`와 일부 demo script에서 사용합니다.
- 현재 URL-to-PDF Docker 기본 실행 경로에는 필수가 아닙니다.

## 디렉터리 구조

```text
scripts/plugin_agents/run_url_to_pdf.py   현재 배포 기준 메인 CLI
s2n_ai/                                   정규화, RAG, Markdown/PDF 생성 코드
docs/security_guides/                     로컬 RAG에 쓰는 보안 가이드 문서
docs/KNOWN_LIMITATIONS.md                 알려진 제한사항
docs/SEVERITY_SCORING.md                  XSS 심각도 산정 기준
serving/                                  선택 사항: FastAPI PEFT inference server
s2nagent/                                 과거/확장용 S2N-Agent task/client/plugin 코드
reports/generated/                        실행 결과 PDF/JSON 출력 위치, Git 제외
storage/                                  ChromaDB/Hugging Face 캐시, Git 제외
adapters/                                 필수 권장: 로컬 PEFT adapter 위치, Git 제외
```

## 요구사항

권장 실행 방식은 Docker입니다.

- Docker
- Docker Compose v2
- 본인이 테스트할 수 있는 취약한 XSS 실습 대상

로컬 Python으로도 실행할 수 있지만, WeasyPrint와 Playwright Chromium의 시스템 의존성 때문에 Docker 실행을 권장합니다.

## 1. 코드 받기와 PEFT adapter 준비

코드는 GitHub에서 받고, 모델 adapter는 Hugging Face에서 받습니다.

```bash
git clone https://github.com/kim-daehyun/s2n-agent-xss-ai.git
cd s2n-agent-xss-ai
```

먼저 Docker 이미지를 빌드합니다. Docker 이미지 안에는 adapter 다운로드에 필요한 Python 패키지가 들어 있습니다.

```bash
docker compose build
```

그 다음 제공 스크립트를 컨테이너 안에서 실행합니다.

```bash
docker compose run --rm s2n-agent-report bash scripts/download_peft_adapter.sh
```

이 스크립트는 아래 Hugging Face repo에서 adapter를 받아옵니다.

```text
emmaemmaemma123/xss-agent-qwen3b-clean-peft
```

다운로드 후 로컬 구조는 이렇게 됩니다.

```text
adapters/
  xss-agent-qwen3b-clean-peft/
    adapter_config.json
    adapter_model.safetensors
    tokenizer.json
    tokenizer_config.json
```

참고로 `run_url_to_pdf.py`는 PEFT adapter가 없으면 기본적으로 Hugging Face에서 자동 다운로드를 시도합니다. 그래도 배포 검증에서는 먼저 위 다운로드 스크립트를 실행해 adapter를 명시적으로 준비하는 방식을 권장합니다.

## 2. Docker 이미지 빌드

```bash
docker compose build
```

기본 이미지 태그는 다음으로 고정되어 있습니다.

```text
s2n-agent-url-to-pdf:0.1.0
```

태그를 바꾸고 싶으면 다음처럼 빌드합니다.

```bash
S2N_REPORT_VERSION=0.1.0 \
S2N_REPORT_IMAGE=s2n-agent-url-to-pdf:0.1.0 \
docker compose build
```

필요하면 `latest`도 별도로 붙일 수 있습니다.

```bash
docker tag s2n-agent-url-to-pdf:0.1.0 s2n-agent-url-to-pdf:latest
```

## 3. DVWA reflected XSS 테스트 예시

DVWA가 호스트 머신에서 `4280` 포트로 떠 있다고 가정합니다.

Docker 컨테이너에서 호스트 머신에 접근할 때는 `host.docker.internal`을 사용합니다.

```bash
docker compose run --rm s2n-agent-report \
  python -B scripts/plugin_agents/run_url_to_pdf.py \
  --url 'http://host.docker.internal:4280/vulnerabilities/xss_r/?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E' \
  --cookie 'PHPSESSID=여기에_본인_세션값; security=low' \
  --output-pdf /app/reports/generated/dvwa_xss_report.pdf \
  --reindex \
  --use-peft-agent \
  --adapter-path /app/adapters/xss-agent-qwen3b-clean-peft
```

성공하면 아래 경로에 PDF와 중간 JSON 파일이 생깁니다.

```text
reports/generated/dvwa_xss_report.pdf
reports/generated/<slug>_s2n_result.json
reports/generated/<slug>_normalized.json
reports/generated/<slug>_rag_contexts.json
```

## 4. Juice Shop 테스트 예시

Juice Shop이 호스트 머신에서 `3000` 포트로 떠 있다고 가정합니다.

```bash
docker compose run --rm s2n-agent-report \
  python -B scripts/plugin_agents/run_url_to_pdf.py \
  --url 'http://host.docker.internal:3000' \
  --output-pdf /app/reports/generated/juice_shop_xss_report.pdf \
  --reindex \
  --use-peft-agent \
  --adapter-path /app/adapters/xss-agent-qwen3b-clean-peft
```

이 경우 스크립트는 Juice Shop 계열 대상으로 판단하면 느린 raw HTTP probe를 줄이고 Playwright Chromium 기반 DOM probe를 우선 실행합니다.

## 5. 기본 CLI 사용법

비대화형 실행을 권장합니다.

```bash
python -B scripts/plugin_agents/run_url_to_pdf.py \
  --url 'http://target.example/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E' \
  --cookie 'name=value; security=low' \
  --output-pdf reports/generated/url_xss_report.pdf \
  --reindex \
  --use-peft-agent \
  --adapter-path adapters/xss-agent-qwen3b-clean-peft
```

옵션 설명:

```text
--url               테스트 대상 URL입니다. 없으면 대화형 입력을 받습니다.
--cookie            선택 사항입니다. 인증이 필요한 실습 환경의 Cookie 헤더입니다.
--output-pdf        PDF 출력 경로입니다.
--timeout           요청/브라우저 timeout 초 단위입니다. 기본값은 25입니다.
--max-candidates    raw HTTP auto-probe 최대 후보 수입니다. 기본값은 80입니다.
--reindex           docs/security_guides 기반 ChromaDB 인덱스를 다시 만듭니다.
--use-peft-agent    기본값입니다. 로컬 PEFT adapter로 XSSAgent 판단을 추가합니다.
--adapter-path      --use-peft-agent 사용 시 adapter 경로입니다.
--adapter-repo      adapter 자동 다운로드에 사용할 Hugging Face repo입니다.
--no-auto-download-adapter adapter가 없을 때 Hugging Face 자동 다운로드를 끕니다.
--allow-peft-fallback PEFT 실패 시 rule-based finding으로 계속 진행합니다.
--no-peft-agent     PEFT 사용을 명시적으로 끕니다. 일반 배포 검증에서는 권장하지 않습니다.
```

대화형 실행도 가능합니다.

```bash
docker compose run --rm s2n-agent-report
```

다만 배포/재현성 측면에서는 `--url`, `--cookie`, `--output-pdf`를 명시하는 방식을 추천합니다.

## 6. URL에 `%3C` 같은 문자가 있을 때 주의

쉘에서 아래처럼 쓰면 안 됩니다.

```bash
printf "http://.../?name=%3Cscript%3E..."
```

`printf`가 `%3C`를 포맷 문자처럼 해석해서 입력이 깨질 수 있습니다.

stdin으로 넘기고 싶다면 아래처럼 `%s` 포맷을 명시하세요.

```bash
printf '%s\n%s\n' \
  'http://host.docker.internal:4280/vulnerabilities/xss_r/?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E' \
  'PHPSESSID=여기에_본인_세션값; security=low' \
| docker compose run --rm s2n-agent-report \
  python -B scripts/plugin_agents/run_url_to_pdf.py \
  --reindex \
  --use-peft-agent \
  --adapter-path /app/adapters/xss-agent-qwen3b-clean-peft
```

가장 안전한 방식은 `--url`, `--cookie` 인자로 넘기는 것입니다.

## 7. PEFT adapter 사용법

기본 Docker 실행은 PEFT adapter를 사용합니다. 사용자가 직접 adapter 파일을 복사할 필요가 없도록 두 가지 경로를 제공합니다.

권장 경로:

```bash
docker compose build
docker compose run --rm s2n-agent-report bash scripts/download_peft_adapter.sh
```

자동 경로:

- `run_url_to_pdf.py` 실행 시 adapter가 없으면 Hugging Face에서 자동 다운로드를 시도합니다.
- 기본 Hugging Face repo는 `emmaemmaemma123/xss-agent-qwen3b-clean-peft`입니다.
- 자동 다운로드를 끄고 싶을 때만 `--no-auto-download-adapter`를 사용합니다.

예시:

```text
adapters/
  xss-agent-qwen3b-clean-peft/
    adapter_config.json
    adapter_model.safetensors
    tokenizer.json
    tokenizer_config.json
```

그리고 다음처럼 실행합니다.

```bash
docker compose run --rm s2n-agent-report \
  python -B scripts/plugin_agents/run_url_to_pdf.py \
  --url 'http://authorized-target.example/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E' \
  --output-pdf /app/reports/generated/peft_report.pdf \
  --reindex \
  --use-peft-agent \
  --adapter-path /app/adapters/xss-agent-qwen3b-clean-peft
```

adapter 파일은 크기가 커서 GitHub 코드 저장소에 직접 올리지 않습니다. 모델 adapter는 Hugging Face에 두고, 코드는 GitHub에 두는 방식으로 배포합니다.

adapter 없이 동작만 빠르게 확인해야 하는 경우에만 아래처럼 명시적으로 PEFT를 끌 수 있습니다.

```bash
docker compose run --rm s2n-agent-report \
  python -B scripts/plugin_agents/run_url_to_pdf.py \
  --url 'http://authorized-target.example/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E' \
  --output-pdf /app/reports/generated/rule_based_report.pdf \
  --reindex \
  --no-peft-agent
```

## 8. 출력 파일

성공 시 다음 파일들이 생성됩니다.

```text
reports/generated/<slug>_s2n_result.json
reports/generated/<slug>_normalized.json
reports/generated/<slug>_rag_contexts.json
reports/generated/<사용자가_지정한_pdf>.pdf
```

XSS가 확인되지 않으면 no-finding PDF를 만들고 종료 코드 `2`로 종료합니다.

## 9. 로컬에서 배포 전 확인하는 방법

타 사용자 입장에서의 확인은 “새 디렉터리에 GitHub repo를 다시 clone해서 진행”하는 방식이 가장 확실합니다.

```bash
cd /tmp
git clone https://github.com/kim-daehyun/s2n-agent-xss-ai.git
cd s2n-agent-xss-ai
docker compose build
docker compose run --rm s2n-agent-report bash scripts/download_peft_adapter.sh
```

코드 문법 확인:

```bash
python3 -m compileall -q s2nagent s2n_ai serving scripts
```

Docker Compose 설정 확인:

```bash
docker compose config
```

DVWA smoke test:

```bash
docker compose build
docker compose run --rm s2n-agent-report \
  python -B scripts/plugin_agents/run_url_to_pdf.py \
  --url 'http://host.docker.internal:4280/vulnerabilities/xss_r/?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E' \
  --cookie 'PHPSESSID=여기에_본인_세션값; security=low' \
  --output-pdf /app/reports/generated/dvwa_smoke.pdf \
  --reindex \
  --use-peft-agent \
  --adapter-path /app/adapters/xss-agent-qwen3b-clean-peft
```

Juice Shop smoke test:

```bash
docker compose run --rm s2n-agent-report \
  python -B scripts/plugin_agents/run_url_to_pdf.py \
  --url 'http://host.docker.internal:3000' \
  --output-pdf /app/reports/generated/juice_shop_smoke.pdf \
  --reindex \
  --use-peft-agent \
  --adapter-path /app/adapters/xss-agent-qwen3b-clean-peft
```

GitHub push 전 제외 대상 확인:

```bash
git ls-files | grep -E 'adapter_model\.safetensors|__pycache__|^storage/|^reports/generated/|^\.trash' || true
```

아무것도 출력되지 않으면 대형 adapter, 캐시, 생성 리포트가 Git 추적 대상에 남아 있지 않은 상태입니다.

더 자세한 타 사용자 관점 검증 체크리스트는 [docs/USER_ACCEPTANCE_TEST.md](docs/USER_ACCEPTANCE_TEST.md)를 참고하세요.

로컬의 단순 XSS 취약 페이지 smoke test 예시:

```bash
docker compose run --rm s2n-agent-report \
  python -B scripts/plugin_agents/run_url_to_pdf.py \
  --url 'http://host.docker.internal:8080/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E' \
  --output-pdf /app/reports/generated/local_xss_peft_smoke.pdf \
  --reindex \
  --use-peft-agent \
  --adapter-path /app/adapters/xss-agent-qwen3b-clean-peft
```

## 10. 배포할 때 추천 흐름

1. Hugging Face repo `emmaemmaemma123/xss-agent-qwen3b-clean-peft`에 adapter 파일을 업로드합니다.
2. `docker compose run --rm s2n-agent-report bash scripts/download_peft_adapter.sh`로 adapter 다운로드가 되는지 확인합니다.
3. DVWA와 Juice Shop 대상으로 Docker smoke test를 한 번씩 실행합니다.
4. 생성된 PDF를 열어서 `All Findings Summary`, Evidence, RAG, Official Reference 섹션을 확인합니다.
5. `reports/generated/`는 Git에 올리지 않습니다.
6. adapter weight는 GitHub 코드 repo에 직접 올리지 않습니다.
7. 아래 명령으로 커밋합니다.

```bash
git add .gitignore .dockerignore Dockerfile docker-compose.yml pyproject.toml README.md docs/KNOWN_LIMITATIONS.md adapters/README.md scripts/download_peft_adapter.sh scripts/plugin_agents/run_url_to_pdf.py s2n_ai/report_generator.py
git add -u
git commit -m "Prepare URL-to-PDF XSS reporter for GitHub distribution"
git tag v0.1.0
```

8. GitHub remote를 연결하고 push합니다.

```bash
git remote add origin https://github.com/kim-daehyun/s2n-agent-xss-ai.git
git branch -M main
git push -u origin main
git push origin v0.1.0
```

## 11. 보안 주의사항

- 허가받은 대상에만 사용하세요.
- 이 도구를 public API로 노출하지 마세요.
- URL 입력을 그대로 HTTP 요청/브라우저 이동에 사용하므로, 서비스화하려면 SSRF 방어가 필요합니다.
- Cookie 값은 민감정보입니다.
- 인증 쿠키를 사용해 생성한 PDF/JSON은 외부에 공유하기 전에 반드시 확인하세요.
- `reports/generated/`는 기본적으로 Git에서 제외됩니다.

## 12. 알려진 제한사항

자세한 내용은 [docs/KNOWN_LIMITATIONS.md](docs/KNOWN_LIMITATIONS.md)를 참고하세요.
심각도 산정 기준은 [docs/SEVERITY_SCORING.md](docs/SEVERITY_SCORING.md)를 참고하세요.

요약하면:

- 완전한 웹 크롤러가 아닙니다.
- payload set은 제한적입니다.
- Juice Shop probe는 특정 검색/DOM 흐름에 맞춰져 있습니다.
- PEFT inference는 CPU/Docker에서 느릴 수 있습니다.
- 공식 레퍼런스는 실시간 웹 검색이 아니라 curated catalog 기반입니다.
- URL runner를 서버로 공개하려면 추가 보안 설계가 필요합니다.

## 라이선스

MIT. [LICENSE](LICENSE)를 참고하세요.
