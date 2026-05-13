# 알려진 제한사항

이 프로젝트는 현재 **로컬에서 실행하는 허가된 XSS 검증 및 PDF 리포트 생성 도구**로 정리되어 있습니다. 공개 웹 스캐너 서비스가 아닙니다.

## 지원 범위

- 주된 지원 흐름은 `URL -> XSS 검증 -> finding 정규화 -> RAG context -> PDF 생성`입니다.
- 현재 실험 기준은 DVWA reflected XSS와 OWASP Juice Shop 검색/DOM 기반 XSS 흐름입니다.
- 다른 애플리케이션에서는 추가 payload, 로그인 처리, 라우팅 처리, 브라우저 조작 로직이 필요할 수 있습니다.

## 보안 경계

- 본인이 소유했거나 명시적으로 허가받은 대상에만 사용해야 합니다.
- `run_url_to_pdf.py`를 public API로 노출하지 마세요.
- 서비스화하려면 SSRF 방어, redirect 제어, private IP 차단, 요청 제한, 감사 로그가 필요합니다.
- 사용자가 제공한 URL로 실제 HTTP 요청과 headless browser 이동이 발생합니다.
- Cookie 헤더를 받기 때문에, 인증된 대상에서 생성한 PDF/JSON은 민감정보로 취급하세요.

## 탐지 한계

- raw HTTP probe는 작은 payload set과 단순 reflection 확인을 사용합니다.
- browser probe는 Juice Shop 계열 검색 route와 DOM 흐름에 맞춰져 있습니다.
- 모든 SPA, 모든 form, 모든 인증 흐름을 자동으로 탐색하지 않습니다.
- payload가 HTTP response에 반사됐다고 해서 항상 브라우저 실행이 확정되는 것은 아닙니다.
- 리포트에는 HTTP reflection인지, browser/DOM observation인지 구분해 기록해야 합니다.

## FastAPI 및 PEFT 한계

- URL-to-PDF 기본 경로는 FastAPI 서버가 없어도 동작합니다.
- FastAPI 서버는 `serving/` 아래에 있는 선택 기능입니다.
- 현재 배포 검증 경로는 PEFT adapter 사용을 기본값으로 둡니다.
- adapter가 없거나 PEFT inference가 실패하면 기본적으로 실패합니다.
- `--allow-peft-fallback`을 명시한 경우에만 rule-based finding으로 계속 진행합니다.
- PEFT adapter weight는 크기 때문에 일반 Git 파일로 커밋하지 않는 것을 권장합니다.
- CPU 환경에서 PEFT inference는 느릴 수 있습니다.

## RAG 및 공식 레퍼런스 한계

- 내부 RAG는 `docs/security_guides/*.md` 파일을 기반으로 합니다.
- 공식 레퍼런스 매핑은 실시간 웹 검색이 아니라 curated catalog 기반입니다.
- 심각도 산정은 OWASP/CVSS/CWE/MDN/PortSwigger 기준을 참고한 내부 정책이며, 정식 CVSS vector 계산기는 아닙니다.
- ChromaDB runtime 데이터는 `storage/` 아래에 생성되며 Git에 올리지 않습니다.

## PDF 렌더링 한계

- PDF 생성은 Docker 이미지에 설치된 WeasyPrint 시스템 라이브러리에 의존합니다.
- 매우 긴 URL, payload, response snippet은 PDF 안정성을 위해 줄바꿈되거나 일부 잘릴 수 있습니다.
- 생성된 PDF/HTML/JSON 파일은 기본적으로 Git에서 제외됩니다.

## 배포 한계

- 현재 추천 배포 방식은 GitHub source + Docker build입니다.
- 대형 모델/adapter 파일은 GitHub Release asset, Git LFS, 사내 artifact 저장소 등 별도 배포 경로를 권장합니다.
- GitHub에 push하기 전에 `adapters/`, `storage/`, `reports/generated/`, `__pycache__/`, backup 파일이 staging되지 않았는지 확인하세요.
