# XSSAgent Baseline Evaluation Report

## 1. Executive Summary

최신 `main` 기준의 XSSAgent baseline 모델(`s2n-agent-xss`)을 100개 test set으로 평가한 결과, 전체 정확도는 **80.00%**입니다.

핵심 판단은 다음과 같습니다.

- 전체적으로 baseline은 **selection**과 **payload planning**에서는 비교적 안정적입니다.
- 가장 큰 병목은 **next_action**입니다. 정확도는 **53.33%**로, 후속 플러그인 선택과 priority 판단이 흔들립니다.
- **false_positive**도 **70.00%**로 개선 여지가 큽니다. 특히 `confirmed`, `inconclusive`, `likely_false_positive`의 경계 판단이 약합니다.
- **payload_planning**은 100%로 집계되었지만, 현재 평가는 exact payload match가 아니라 schema/필수 필드 존재 여부 중심이므로 “실제 payload 품질이 완벽하다”는 의미로 해석하면 안 됩니다.

비유하면, 현재 모델은 “XSS를 봐야 하는지”와 “대략 어떤 payload 구조가 필요한지”는 꽤 맞히지만, “이게 진짜 취약점인지 애매한지”와 “다음에 어떤 보안 검사를 이어가야 하는지”에서는 아직 판단 기준이 덜 정리된 상태입니다.

---

## 2. Evaluation Context

| 항목 | 값 |
|---|---|
| Baseline model | `s2n-agent-xss` |
| Runtime | Ollama |
| Agent | `xss_agent` |
| Test set | `data/plugin_agents/xss/test.jsonl` |
| Evaluation details | `baseline_eval_rerun_details.json` 기준 |
| Total test cases | 100 |
| Passed | 80 |
| Failed | 20 |
| Overall accuracy | 80.00% |

---

## 3. Overall Result

| Metric | Count | Rate |
|---|---:|---:|
| Total | 100 | 100.00% |
| Passed | 80 | 80.00% |
| Failed | 20 | 20.00% |

---

## 4. Result by Task

| Task | Total | Passed | Failed | Accuracy |
|---|---:|---:|---:|---:|
| `payload_planning` | 25 | 25 | 0 | 100.00% |
| `selection` | 30 | 26 | 4 | 86.67% |
| `false_positive` | 30 | 21 | 9 | 70.00% |
| `next_action` | 15 | 8 | 7 | 53.33% |
| **Overall** | **100** | **80** | **20** | **80.00%** |

---

## 5. Task별 해석

### 5.1 `payload_planning`: 25/25, 100.00%

`payload_planning`은 모든 케이스가 통과했습니다.

다만 주의할 점이 있습니다. 현재 평가 기준은 payload의 exact match가 아니라 다음 조건 중심입니다.

- JSON schema가 유효한지
- `payloads`가 존재하는지
- `strategy`가 존재하는지
- `context_notes`가 존재하는지

따라서 이 결과는 “payload planning output format은 안정적이다”에 가깝습니다. 실제 payload 전략이 expected와 완전히 동일하다는 의미는 아닙니다.

예를 들어 일부 `html_body`, `json_value` 케이스에서는 실제 출력 payload가 expected와 다르지만, schema와 필수 필드가 충족되어 PASS 처리되었습니다. 그러므로 후속 개선에서는 payload 품질 평가를 더 엄격하게 만들 수 있습니다.

### 5.2 `selection`: 26/30, 86.67%

`selection`은 XSS plugin 실행 여부 판단입니다. 전체적으로는 안정적입니다.

실패한 4건 모두 `should_run` 자체는 맞혔지만, `context_known`이 실패한 케이스입니다. 즉, “XSS를 돌리지 말아야 한다”는 큰 판단은 맞았지만, 해당 endpoint가 왜 XSS 대상이 아닌지에 대한 context 분류가 부족했습니다.

주요 실패 패턴:

- static asset을 `unknown` context로 처리
- file upload surface를 `unknown` context로 처리
- login form only surface를 `unknown` context로 처리

이는 fine-tuning에서 negative surface taxonomy를 더 명확히 학습시키면 개선될 가능성이 큽니다.

### 5.3 `false_positive`: 21/30, 70.00%

`false_positive`는 가장 중요한 개선 대상 중 하나입니다.

주요 실패는 두 가지입니다.

1. 실제 executable XSS evidence인 `confirmed_img_onerror` 계열을 `likely_false_positive`로 낮게 판단
2. 단순 반사이지만 실행 가능성이 불명확한 `attribute_reflection_only`, `plain_reflection` 계열을 `inconclusive`가 아니라 `likely_false_positive`로 판단

즉, 현재 모델은 evidence가 애매하면 대체로 `likely_false_positive` 쪽으로 수렴하는 경향이 있습니다. fine-tuning에서는 아래 경계를 명확히 학습해야 합니다.

- `confirmed`: unescaped executable HTML/event handler evidence
- `inconclusive`: reflected but not clearly executable evidence
- `likely_false_positive`: escaped, inert, not reflected, or sanitized evidence

### 5.4 `next_action`: 8/15, 53.33%

`next_action`은 가장 낮은 성능을 보였습니다.

주요 실패는 다음 두 가지입니다.

1. 모든 주요 후속 플러그인이 이미 completed된 상황에서 `next_action=stop`은 맞혔지만, priority를 `low`가 아니라 `high`로 판단
2. JWT/session follow-up이 필요한 상황에서 `jwt`가 아니라 `sql`을 추천

즉, 현재 모델은 “무엇을 다음에 해야 하는가”에 대한 정책 판단이 약합니다. 특히 XSS 이후 후속 플러그인 추천 기준에서 CSRF/JWT/SQL의 경계가 흔들립니다.

fine-tuning에서는 `completed_plugins`, `finding severity`, `sitemap surface`, `session/auth 관련 endpoint 존재 여부`를 함께 보고 next action을 결정하도록 학습해야 합니다.

---

## 6. Failure Pattern Summary

| Failure Pattern | Count | 설명 | 개선 방향 |
|---|---:|---|---|
| `confirmed_img_onerror` → `likely_false_positive` | 4 | executable HTML/event handler evidence를 confirmed로 보지 못함 | unescaped executable context를 `confirmed`로 강하게 학습 |
| `attribute_reflection_only` / `plain_reflection` → `likely_false_positive` | 5 | 단순 반사/실행 불명확 케이스를 `inconclusive`로 두지 못함 | reflected-but-not-executable 경계를 `inconclusive`로 학습 |
| `xss_stop_all_completed` priority mismatch | 4 | `next_action=stop`은 맞지만 priority를 `high`로 판단 | all completed + low severity 상황은 `priority=low`로 학습 |
| `xss_to_jwt` → `sql` | 3 | session/JWT 후속 분석이 필요한 상황에서 SQL을 추천 | auth/session/JWT surface와 SQL surface 구분 학습 |
| negative selection context unknown | 4 | static/upload/login-only surface를 unknown context로 처리 | negative surface taxonomy 보강 |

---

## 7. Failed IDs

### 7.1 `false_positive` failures

- `xss-fp-confirmed_img_onerror-0011`
- `xss-fp-confirmed_img_onerror-0012`
- `xss-fp-confirmed_img_onerror-0008`
- `xss-fp-confirmed_img_onerror-0009`
- `xss-fp-attribute_reflection_only-0028`
- `xss-fp-attribute_reflection_only-0008`
- `xss-fp-attribute_reflection_only-0023`
- `xss-fp-attribute_reflection_only-0012`
- `xss-fp-plain_reflection-0026`

### 7.2 `next_action` failures

- `xss-next-xss_stop_all_completed-0026`
- `xss-next-xss_stop_all_completed-0010`
- `xss-next-xss_stop_all_completed-0029`
- `xss-next-xss_stop_all_completed-0028`
- `xss-next-xss_to_jwt-0029`
- `xss-next-xss_to_jwt-0003`
- `xss-next-xss_to_jwt-0025`

### 7.3 `selection` failures

- `xss-selection-negative-0036`
- `xss-selection-negative-0007`
- `xss-selection-negative-0006`
- `xss-selection-negative-0030`

### 7.4 `payload_planning` failures

없음.

---

## 8. Fine-tuning 관점에서의 우선순위

### Priority 1. `next_action` policy learning

가장 먼저 개선해야 할 영역입니다.

현재 정확도는 53.33%로 가장 낮습니다. 특히 JWT/session follow-up과 SQL follow-up을 혼동하고, stop 상황에서도 priority를 과하게 높이는 문제가 있습니다.

학습 데이터에서 다음 조건을 명확히 해야 합니다.

- 이미 completed된 plugin은 다시 추천하지 않음
- low severity + no sensitive follow-up surface이면 `stop`, `priority=low`
- authenticated/session/JWT 관련 surface가 있으면 `jwt`
- state-changing form/action이 있으면 `csrf`
- SQL parameterized surface evidence가 있을 때만 `sql`

### Priority 2. False positive verdict boundary

`confirmed`, `inconclusive`, `likely_false_positive`의 경계가 아직 약합니다.

특히 다음 규칙을 강화해야 합니다.

- `<img src=x onerror=...>`처럼 executable event handler가 unescaped로 존재하면 `confirmed`
- reflected only but not executable이면 `inconclusive`
- escaped, inert, not reflected이면 `likely_false_positive`

### Priority 3. Negative selection context taxonomy

`selection`은 큰 판단은 맞지만 negative context 분류가 약합니다.

보강할 negative surface:

- `static_asset`
- `file_upload_surface`
- `login_form_only`
- `download/path traversal surface`
- `no reflected user-controlled input`

---

## 9. Baseline으로서의 의미

이 baseline은 fine-tuning 전 기준점입니다.

이후 LoRA fine-tuned 모델인 `s2n-agent-xss-ft`를 만들면, 동일한 `test.jsonl`과 동일한 `evaluate_xss_agent.py`로 평가하여 아래와 같이 비교합니다.

| Task | Baseline | Fine-tuned | Delta |
|---|---:|---:|---:|
| `payload_planning` | 100.00% | TBD | TBD |
| `selection` | 86.67% | TBD | TBD |
| `false_positive` | 70.00% | TBD | TBD |
| `next_action` | 53.33% | TBD | TBD |
| **Overall** | **80.00%** | **TBD** | **TBD** |

---

## 10. Conclusion

Baseline 모델은 전체 80.00% 정확도를 보였으며, XSS plugin 실행 여부 판단과 output schema 생성은 비교적 안정적입니다.

그러나 fine-tuning의 실질적 개선 목표는 명확합니다.

1. `next_action`의 후속 플러그인 선택과 priority 정책 안정화
2. `false_positive`에서 confirmed / inconclusive / likely_false_positive 경계 강화
3. negative selection context 분류 보강

따라서 PR4의 LoRA fine-tuning은 단순히 전체 accuracy를 올리는 것이 아니라, 특히 `next_action`과 `false_positive`의 정책성 판단을 개선하는 방향으로 해석해야 합니다.
