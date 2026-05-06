# S2N-Agent 플러그인별 전담 모델 개발 계획서

> 목적: S2N의 12개 취약점 플러그인을 각각 독립적으로 판단하는 전담 에이전트/모델 단위로 확장한다.
> 기준 문서: `docs/plan.md`, `docs/s2n-README.ko.md`
> 현 repo 구현 기준: `s2nagent/agent.py`, `s2nagent/tasks/`, `s2nagent/plugins/s2n_agent_plugin.py`, `s2nagent/constants.py`
> 최종 검증: 2026-05-06

---

## 1. 결론

플러그인별 모델을 “개별적으로 활동”하게 만드는 목표에는 다음 구조가 가장 적합하다.

```
SiteMap / DOM / Response
  -> router model: 실행 후보 플러그인 top-k 선정
  -> plugin agent registry: 플러그인별 전담 모델 호출
  -> plugin execution: S2N 플러그인이 실제 검사 수행
  -> result agents: FP 필터, 후속 페이로드, 다음 액션 계획
  -> ScanReport / agent_state / PluginResult.metadata
```

권장 방식은 **공통 베이스 모델 + 플러그인별 LoRA/QLoRA 어댑터 + 라우터**다.

- 12개 풀 모델을 각각 따로 학습/배포하는 방식은 격리는 좋지만, 로컬 추론 비용과 평가 부담이 너무 크다.
- 단일 모델에 프롬프트만 바꾸는 방식은 가장 빠르지만, 플러그인별 전문성이 약하고 회귀 원인 분석이 어렵다.
- 공통 베이스 모델에 플러그인별 어댑터를 붙이면 모델 이름은 `s2n-agent-xss`처럼 독립적으로 운영하면서도 학습/배포 비용을 통제할 수 있다.

따라서 v1 목표는 “12개 전담 모델 엔드포인트”가 아니라 “12개 전담 에이전트 스펙 + 우선순위 어댑터 배포”로 둔다.

---

## 2. 전략 검증

| 전략 | 장점 | 단점 | 판정 |
| --- | --- | --- | --- |
| 12개 풀 모델 | 완전 격리, 플러그인별 독립 튜닝 쉬움 | 12배 저장공간/메모리, 느린 평가, 운영 복잡도 큼 | v1 비권장 |
| 단일 모델 + 프롬프트 프로파일 | 가장 빠른 구현, 현재 코드와 거의 동일 | 전문성 부족, 플러그인별 품질 추적 어려움 | 부트스트랩/저위험 플러그인용 |
| 공통 베이스 + 플러그인별 LoRA/QLoRA | 독립 모델처럼 호출 가능, 비용 통제, 회귀 추적 쉬움 | 라우터/어댑터 레지스트리 필요 | 권장 |

선택 기준:

- XSS, SQL Injection, File Upload, JWT는 데이터와 위험도가 높으므로 v1에서 우선 분리한다.
- OS Command, Path Traversal, Sensitive Files, React2Shell은 v1.5에서 분리한다.
- CSRF, Brute Force, Soft Brute Force, Autobot은 초기에는 공통 모델 + 프롬프트 프로파일로 운영하고, 평가 지표가 부족하면 어댑터를 추가한다.

---

## 3. 현재 구조

S2N 스캐너의 기준 흐름:

```
Crawler -> SiteMap -> Plugin -> ScanReport
```

S2N-Agent 현 구현의 기준 흐름:

```
s2nagent/agent.py
  -> PluginSelectionTask
  -> PayloadPlanningTask
  -> FalsePositiveTask
  -> MultiStepPlannerTask

s2nagent/plugins/s2n_agent_plugin.py
  -> pre_scan: sitemap 분석, 플러그인 권고, payload 계획
  -> run: assist 모드 권고 로그
  -> post_scan: 결과 해석, FP 필터, 다음 액션 저장
  -> on_finding: 실시간 finding 분석
```

현재 Task A-D 출력 JSON은 유지한다. 플러그인별 전담 에이전트의 공통 출력은 Task A-D 위에 얹는 런타임 envelope로 정의한다.

---

## 4. 공통 계약

### 4-1. 모델 Task 출력

현재 코드와 학습/평가 파이프라인이 기대하는 Task별 strict JSON은 유지한다.

| Task | 목적 | 출력 |
| --- | --- | --- |
| A | Plugin Selection | `{"plugin": "...", "confidence": 0-100, "reason": "..."}` |
| B | Payload Planning | `{"payloads": [...], "bypass_variants": [...], "strategy": "...", "context_notes": "..."}` |
| C | False Positive Filter | `{"verdict": "confirmed|likely_false_positive", "reason": "...", "confidence": 0-100}` |
| D | Multi-step Planner | `{"next_action": "plugin|stop", "reason": "...", "priority": "high|medium|low"}` |

### 4-2. 플러그인 에이전트 envelope

플러그인별 전담 에이전트는 Task 결과를 조합해 아래 구조를 `ScanContext.session_data["agent_state"]`와 `PluginResult.metadata["agent_decision"]`에 저장한다.

```json
{
  "agent": "xss_agent",
  "plugin": "xss",
  "model": "s2n-agent-xss",
  "should_run": true,
  "confidence": 91,
  "reason": "reflected text input and html_attribute context detected",
  "task_outputs": {
    "selection": {"plugin": "xss", "confidence": 91, "reason": "..."},
    "payload_plan": {"payloads": ["<svg/onload=alert(1)>"], "bypass_variants": [], "strategy": "..."},
    "false_positive": null,
    "next_plan": null
  },
  "next_action": "run_plugin",
  "metadata": {
    "agent_decision_version": "v1",
    "source": "plugin_agent_registry"
  }
}
```

중요한 제약:

- 모델은 HTTP 요청, 쿠키/세션 관리, DOM 파싱을 직접 수행하지 않는다.
- 모델은 실행 여부, 페이로드 후보, 결과 해석, 다음 액션만 판단한다.
- 실제 공격 실행과 검증은 S2N 플러그인이 담당한다.

---

## 5. 런타임 설계

### 5-1. 에이전트 레지스트리

새 모듈 후보:

```
s2nagent/plugin_agents/
  __init__.py
  base.py
  registry.py
  xss.py
  sqlinjection.py
  oscommand.py
  csrf.py
  file_upload.py
  jwt.py
  brute_force.py
  soft_brute_force.py
  path_traversal.py
  sensitive_files.py
  react2shell.py
  autobot.py
```

`registry.py`는 플러그인 이름을 전담 에이전트와 모델명으로 매핑한다.

```python
PLUGIN_AGENT_REGISTRY = {
    "xss": {"agent": XSSAgent, "model": "s2n-agent-xss", "adapter": "lora-out/xss"},
    "sqlinjection": {"agent": SQLInjectionAgent, "model": "s2n-agent-sqli", "adapter": "lora-out/sqli"},
    "jwt": {"agent": JWTAgent, "model": "s2n-agent-jwt", "adapter": "lora-out/jwt"},
}
```

### 5-2. 실행 모드

| Mode | 동작 |
| --- | --- |
| `off` | 기존 S2N 실행. 모델 호출 없음 |
| `assist` | 라우터와 전담 에이전트가 권고만 남김. 실행은 기존 플러그인 목록 |
| `smart` | 라우터가 top-k 후보를 고르고, 후보 전담 에이전트가 `should_run`을 판단 |
| `aggressive` | top-k 전담 에이전트를 반복 호출해 멀티스텝 체인을 계획 |

`smart` 모드는 전체 12개 모델을 매번 호출하지 않는다. 라우터가 후보를 줄이고, 후보 에이전트만 독립 판단한다.

### 5-3. 데이터 흐름

```
pre_scan(ctx)
  -> RouterAgent.select_candidates(ctx.sitemap, ctx.dom)
  -> PluginAgent.evaluate(ctx)
  -> agent_state["plugin_agent_decisions"] 저장
  -> 선택된 플러그인의 payload plan 저장

plugin.run(ctx)
  -> S2N 플러그인이 실제 검사 수행

on_finding(finding)
  -> 해당 plugin agent 또는 공통 FP agent가 실시간 판정

post_scan(ctx)
  -> 전담 agent 결과와 finding을 합쳐 next_action 계획
  -> PluginResult.metadata["agent_decision"] 저장
```

---

## 6. 플러그인별 전담 에이전트

| Agent | Plugin | 우선순위 | 전담 역할 | 사용 Task | v1 모델 |
| --- | --- | --- | --- | --- | --- |
| `xss_agent` | `xss` | P0 | DOM/반사 컨텍스트 판단, XSS payload 계획 | A, B, C, D | `s2n-agent-xss` |
| `sqlinjection_agent` | `sqlinjection` | P0 | 파라미터/DB 오류/블라인드 SQLi 판단 | A, B, C, D | `s2n-agent-sqli` |
| `file_upload_agent` | `file_upload` | P0 | 업로드 폼, 확장자 우회, 실행 가능 경로 판단 | A, B, C, D | `s2n-agent-upload` |
| `jwt_agent` | `jwt` | P0 | JWT 알고리즘/서명/클레임 변조 판단 | A, B, C, D | `s2n-agent-jwt` |
| `oscommand_agent` | `oscommand` | P1 | shell-like 파라미터, 명령 출력 증거 해석 | A, B, C, D | prompt profile |
| `path_traversal_agent` | `path_traversal` | P1 | file/path 파라미터, OS별 traversal payload 계획 | A, B, C, D | prompt profile |
| `sensitive_files_agent` | `sensitive_files` | P1 | 백업/설정/소스 노출 경로 우선순위화 | A, B, C | prompt profile |
| `react2shell_agent` | `react2shell` | P1 | React/SSR/template injection 신호 판단 | A, B, C, D | prompt profile |
| `csrf_agent` | `csrf` | P2 | 상태 변경 폼과 토큰/SameSite 증거 해석 | A, C | prompt profile |
| `brute_force_agent` | `brute_force` | P2 | 로그인 표면, 계정 후보, 차단 여부 판단 | A, B, C | prompt profile |
| `soft_brute_force_agent` | `soft_brute_force` | P2 | rate limit 존재 시 저속 시도 전략 판단 | A, B, C, D | prompt profile |
| `autobot_agent` | `autobot` | P2 | 범용 자동 탐색 결과의 후속 플러그인 연결 | A, C, D | prompt profile |

---

## 7. 모델/어댑터 계획

### 7-1. 기본 모델

- 공통 베이스: `qwen2.5-coder:7b`
- 기본 Ollama 모델: `s2n-agent`
- 기준 파일: `s2nagent/models/Modelfile`

### 7-2. v1 전담 모델명

```
s2n-agent-router
s2n-agent-xss
s2n-agent-sqli
s2n-agent-upload
s2n-agent-jwt
```

초기에는 각 모델명을 Ollama에 별도 등록하되, 같은 베이스 모델과 다른 LoRA adapter를 사용한다. 학습 데이터가 부족한 플러그인은 `s2n-agent` 공통 모델에 plugin-specific system prompt만 적용한다.

### 7-3. v1.5 확장 모델명

```
s2n-agent-oscommand
s2n-agent-path
s2n-agent-sensitive-files
s2n-agent-react2shell
```

### 7-4. 풀 모델 분리 기준

풀 모델 분리는 다음 조건을 모두 만족할 때만 검토한다.

- 플러그인별 adapter가 공통 모델 대비 평가 지표를 10%p 이상 개선한다.
- 해당 플러그인의 월간 실행 비율이 높아 독립 배포 비용을 정당화한다.
- adapter 간 회귀가 반복되어 adapter 방식으로 격리가 충분하지 않다.

---

## 8. 학습 데이터 계획

최종 학습 파일은 현재처럼 ChatML JSONL을 유지한다.

```json
{
  "messages": [
    {"role": "system", "content": "plugin-specific system prompt"},
    {"role": "user", "content": "task input JSON"},
    {"role": "assistant", "content": "task output strict JSON"}
  ]
}
```

내부 원천 데이터에는 아래 필드를 둔다.

```json
{
  "plugin": "xss",
  "agent": "xss_agent",
  "task": "payload_planning",
  "context": {"url": "/search?q=test", "dom": "<input name='q'>"},
  "evidence": {"response_snippet": "reflected q"},
  "expected_json": {"payloads": ["<svg/onload=alert(1)>"], "strategy": "..."}
}
```

데이터셋 구성:

| 묶음 | 대상 | 수량 목표 |
| --- | --- | --- |
| Router | 12개 플러그인 후보 선정 | 1,200 |
| P0 adapters | XSS, SQLi, Upload, JWT | 플러그인당 600-1,000 |
| P1 profiles/adapters | OS Command, Path Traversal, Sensitive Files, React2Shell | 플러그인당 300-600 |
| P2 profiles | CSRF, Brute Force, Soft Brute Force, Autobot | 플러그인당 200-400 |
| False Positive | plugin별 confirmed/FP 균형 | 1,200+ |

---

## 9. 평가 지표

| 지표 | 목표 | 설명 |
| --- | --- | --- |
| Router top-1 정확도 | 80%+ | 가장 적합한 플러그인 1개 예측 |
| Router top-3 recall | 95%+ | 후보 3개 안에 정답 포함 |
| Plugin `should_run` F1 | 85%+ | 전담 에이전트 실행 여부 판단 |
| Payload 유효률 | 70%+ | 플러그인이 실제 사용할 수 있는 payload 비율 |
| False Positive 감소 | 30%+ | 기존 계획의 Task C 지표 유지 |
| JSON 파싱 성공률 | 95%+ | 모든 전담 모델 strict JSON 준수 |
| Latency budget | smart 2회 이하, aggressive top-k | 한 스캔 단계에서 모델 호출 수 제한 |

---

## 10. 로드맵

| 단계 | 목표 | 산출물 |
| --- | --- | --- |
| Week 1 | 계약 정리 | `PluginAgentDecision` envelope, registry 설계, Task A-D 호환성 유지 |
| Week 2 | Router + P0 agent | router, xss/sqli/upload/jwt agent skeleton, prompt profiles |
| Week 3 | P0 adapter 학습 | plugin별 JSONL 생성, LoRA 학습, Ollama 모델명 등록 |
| Week 4 | 통합/평가 | smart/aggressive 연결, `agent_state`/metadata 기록, benchmark |
| Week 5+ | P1/P2 확장 | OS Command, Path Traversal, Sensitive Files, React2Shell adapter 추가 |

---

## 11. 구현 체크리스트

- `s2nagent/constants.py`의 12개 플러그인 목록과 registry 키를 일치시킨다.
- `PluginSelectionTask`, `PayloadPlanningTask`, `FalsePositiveTask`, `MultiStepPlannerTask`의 기존 출력 JSON은 깨지지 않게 유지한다.
- 공통 envelope는 task parser가 아니라 orchestrator 계층에서 만든다.
- `S2NAgentPlugin.pre_scan`은 router 결과와 plugin agent 결정을 `agent_state["plugin_agent_decisions"]`에 저장한다.
- `S2NAgentPlugin.post_scan`은 `PluginResult.metadata["agent_decision"]`에 최종 판단을 기록한다.
- `assist` 모드는 실행을 바꾸지 않고 권고만 남긴다.
- `smart` 모드는 router top-k와 `should_run`으로 실행 후보를 제한한다.
- `aggressive` 모드는 next_action을 반복 계획하되 모델 호출 수와 스캔 반복 횟수를 제한한다.

---

## 12. 문서 반영 범위

`docs/plan.md`는 전체 S2N-Agent 파인튜닝 계획의 기준 문서로 유지한다. 이 문서는 그 하위 계획으로, 플러그인별 전담 에이전트와 모델 분리 전략을 구체화한다.

`docs/s2n-README.ko.md`의 사용자 관점은 유지한다.

- CLI는 `--ai-mode`, `--ai-model`, `--ai-endpoint` 중심으로 설명한다.
- S2N 플러그인은 실제 공격 실행 주체로 설명한다.
- S2N-Agent 모델은 판단/계획/해석 계층으로 설명한다.
