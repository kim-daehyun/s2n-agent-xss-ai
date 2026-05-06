# XSSAgent 평가 리포트

## 1. 평가 개요

| 항목 | 내용 |
|---|---|
| 평가 대상 | XSSAgent |
| 평가 모델 | s2n-agent-xss |
| 평가 방식 | synthetic XSSAgent dataset 기반 평가 |
| 평가 데이터 | data/plugin_agents/xss/test.jsonl |
| 평가 스크립트 | scripts/plugin_agents/evaluate_xss_agent.py |

---

## 2. 전체 결과 요약

| Metric | Value |
|---|---:|
| Total samples |  |
| Passed samples |  |
| Overall accuracy |  |

---

## 3. Task별 결과

| Task | Total | Passed | Accuracy |
|---|---:|---:|---:|
| selection |  |  |  |
| payload_planning |  |  |  |
| false_positive |  |  |  |
| next_action |  |  |  |

---

## 4. 주요 확인 사항

### 4-1. Selection

확인할 내용:

- XSS가 필요한 경우 `should_run=true`를 반환하는가
- XSS가 아닌 경우 `should_run=false`를 반환하는가
- `html_attribute`, `html_body`, `js_string`, `json_value`, `url_param` 등의 context를 안정적으로 분류하는가

### 4-2. Payload Planning

확인할 내용:

- `payloads`가 list 형태로 반환되는가
- `bypass_variants`가 list 형태로 반환되는가
- `strategy`가 포함되는가
- `context_notes`가 포함되는가
- context별 전략이 적절한가

### 4-3. False Positive

확인할 내용:

- unescaped executable reflection을 `confirmed`로 판단하는가
- HTML escaped reflection을 `likely_false_positive`로 판단하는가
- evidence가 response body에 없으면 `likely_false_positive`로 판단하는가
- 단순 반사지만 실행 context가 불명확한 경우 `inconclusive`로 판단하는가

### 4-4. Next Action

확인할 내용:

- 이미 완료한 plugin을 다시 추천하지 않는가
- XSS 이후 state-changing form이 있으면 `csrf`를 추천하는가
- admin/file route가 있으면 `path_traversal`을 추천하는가
- token/JWT surface가 있으면 `jwt`를 추천하는가
- 후속 공격면이 부족하면 `stop`을 반환하는가

---

## 5. 실패 케이스 분석

| Sample ID | Task | Expected | Actual | 원인 |
|---|---|---|---|---|
|  |  |  |  |  |

---

## 6. 개선 필요 사항

- [ ] selection confidence 보정 기준 개선
- [ ] context별 payload planning 정교화
- [ ] false positive 판단 기준 데이터셋 확장
- [ ] next action 우선순위 규칙 개선
- [ ] DVWA/Juice Shop 기반 실제 샘플 추가

---

## 7. 결론

이번 평가는 XSSAgent가 단일 데모 입력이 아니라 여러 synthetic XSS/비XSS 상황에서 일관되게 동작하는지 확인하기 위한 baseline 평가이다.

이 결과는 이후 fine-tuning 전후 성능 비교의 기준선으로 사용한다.