# XSS 심각도 산정 기준

이 프로젝트의 `risk_score`는 정식 CVSS vector 계산 결과가 아니다. URL-to-PDF 리포트에서 발견된 XSS를 일관되게 설명하기 위한 내부 정규화 점수다.

다만 단순히 `XSS 발견 = HIGH`로 고정하지 않고, 다음 외부 기준을 참고해 evidence 기반으로 산정한다.

- OWASP Risk Rating Methodology: 위험도를 likelihood와 impact의 조합으로 판단한다.
- FIRST CVSS v3.1 Qualitative Severity Rating Scale: Low, Medium, High, Critical 같은 정성 등급과 점수 band를 참고한다.
- CWE-79: XSS를 사용자 입력이 웹 페이지 생성 과정에서 적절히 neutralize되지 않아 브라우저에서 실행 가능한 코드가 되는 약점으로 본다.
- MDN XSS 문서: XSS가 같은 출처 컨텍스트에서 코드 실행, 페이지 조작, 인증된 요청 수행으로 이어질 수 있음을 근거로 삼는다.
- OWASP/PortSwigger XSS 자료: reflected, DOM, stored XSS의 exploitability와 context-aware output encoding 필요성을 근거로 삼는다.

## 산정 방식

1. 스캐너 evidence에서 reflection, script-capable payload, DOM 실행 흔적, stored 여부, 민감 surface 여부를 추출한다.
2. OWASP 방식에 맞춰 likelihood와 impact를 각각 0-9 범위로 계산한다.
3. likelihood와 impact를 가중 평균해 0-100 risk score를 먼저 계산한다.
4. 계산된 risk score가 들어간 범위에 따라 최종 severity를 정한다.
5. 리포트에는 원본 scanner severity와 재산정된 severity를 함께 남긴다.

## Risk score 공식

```text
risk_score = round(((likelihood_score * 0.45) + (impact_score * 0.55)) / 9 * 100)
```

impact를 likelihood보다 조금 높게 반영한다. XSS는 stored 여부, 세션/토큰/관리자 화면 영향, 민감 데이터 접근 가능성처럼 실제 피해 범위가 우선순위 결정에 중요하기 때문이다.

## Severity range

| Risk score | Severity |
|---:|---|
| 90-100 | CRITICAL |
| 70-89 | HIGH |
| 40-69 | MEDIUM |
| 10-39 | LOW |
| 0-9 | INFO |

## XSS 예시 기준

| 상황 | 대표 severity |
|---|---|
| Stored XSS이고 관리자/세션/토큰 등 민감 context 영향 가능 | CRITICAL |
| Reflected 또는 DOM XSS에서 script-capable payload가 확인되고 URL parameter로 재현 가능 | HIGH |
| 반사나 DOM sink는 확인됐지만 실행 조건이 제한적이거나 민감 영향이 명확하지 않음 | MEDIUM |
| 입력 반사 또는 encoding 미흡 신호는 있으나 실행 가능성이 낮음 | LOW |
| 직접적인 exploit evidence 없이 참고성 정보만 존재 | INFO |

## 면접 설명용 요약

초기 버전에서는 confirmed XSS를 보수적으로 HIGH로 분류했다. 현재 버전은 OWASP Risk Rating의 likelihood/impact 모델을 기반으로 reflection, 실행 가능 payload, stored/DOM 여부, URL 접근성, confidence, 민감 surface를 먼저 점수화한다. 그 다음 0-100 risk score를 계산하고, FIRST CVSS의 qualitative severity band 개념을 참고한 범위표로 severity를 결정한다. 그리고 Hybrid RAG가 매칭한 OWASP, CWE, MDN, PortSwigger, FIRST CVSS reference를 리포트의 근거로 함께 남긴다.

따라서 이 점수는 공식 CVSS 점수라고 주장하지 않는다. 대신 공식 기준을 참고한, 설명 가능하고 반복 가능한 XSS 리포트용 severity 산정 정책이다.
