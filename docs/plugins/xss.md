# XSS 전담 Agent / Model 개발 설계서

> 상위 문서: `docs/plugin-plan.md`, `docs/plan.md`
> 대상 플러그인: `xss`
> 전담 agent: `xss_agent`
> 전담 모델명: `s2n-agent-xss`
> 우선순위: P0
> 최종 검증: 2026-05-06

---

## 1. 목표

`xss_agent`는 S2N의 XSS 플러그인을 대체하지 않는다. XSS 가능성이 높은 입력 표면을 판단하고, 컨텍스트에 맞는 payload 후보를 계획하며, 스캔 결과가 실제 반사/실행 증거인지 해석하는 전담 판단 계층이다.

```
SiteMap / DOM / Response
  -> RouterAgent: xss 후보 포함 여부 판단
  -> XSSAgent: should_run + payload plan + FP 판단
  -> S2N xss plugin: 실제 HTTP 요청과 검증 수행
  -> XSSAgent: finding 해석 + 후속 액션 제안
```

핵심 원칙:

- 모델은 HTTP 요청을 직접 보내지 않는다.
- 모델은 쿠키, 세션, 브라우저 실행, DOM 파싱을 직접 수행하지 않는다.
- 모델은 strict JSON만 반환한다.
- 실제 공격 실행과 검증은 S2N `xss` 플러그인이 담당한다.
- XSS 판단 결과는 `ScanContext.session_data["agent_state"]`와 `PluginResult.metadata["agent_decision"]`에 기록한다.

---

## 2. 책임 범위

### 2-1. `xss_agent`가 하는 일

- URL, form, input, DOM snippet, sitemap summary를 보고 XSS 실행 가치가 있는지 판단한다.
- XSS injection context를 추론한다.
- 컨텍스트에 맞는 payload 후보와 우회 변형을 우선순위화한다.
- XSS finding의 evidence와 response snippet을 보고 confirmed/false positive를 판정한다.
- XSS 결과 이후 실행할 다음 플러그인을 제안한다.

### 2-2. `xss_agent`가 하지 않는 일

- 직접 HTTP 요청 전송
- 브라우저 자동화 또는 JavaScript 실행 검증
- 세션/쿠키 갱신
- raw HTML 전체 파싱
- S2N plugin 결과 조작

---

## 3. 런타임 위치

### 3-1. 파일 구조 제안

```text
s2nagent/plugin_agents/
  __init__.py
  base.py
  registry.py
  xss.py

s2nagent/models/
  Modelfile
  Modelfile.xss

data/plugin_agents/xss/
  raw.jsonl
  train.jsonl
  valid.jsonl
  test.jsonl
```

### 3-2. Registry 등록

```python
PLUGIN_AGENT_REGISTRY = {
    "xss": {
        "agent_id": "xss_agent",
        "plugin": "xss",
        "class": XSSAgent,
        "model": "s2n-agent-xss",
        "fallback_model": "s2n-agent",
        "adapter": "lora-out/xss",
        "priority": "P0",
        "tasks": ["selection", "payload_planning", "false_positive", "multi_step"],
    },
}
```

### 3-3. 호출 흐름

```text
S2NAgentPlugin.pre_scan(ctx)
  -> RouterAgent.select_candidates(...)
  -> if "xss" in router.top_k:
       XSSAgent.evaluate_target(...)
       XSSAgent.plan_payloads(...)
       agent_state["plugin_agent_decisions"].append(decision)

S2N xss plugin.run(ctx)
  -> 실제 XSS payload 시도
  -> finding 생성

S2NAgentPlugin.on_finding(finding)
  -> if finding.plugin == "xss":
       XSSAgent.filter_false_positive(...)

S2NAgentPlugin.post_scan(ctx)
  -> XSSAgent.plan_next_action(...)
  -> PluginResult.metadata["agent_decision"] 기록
```

---

## 4. 판단 대상

### 4-1. XSS 실행 신호

| 신호 | 예 | 가중치 |
| --- | --- | --- |
| 사용자 입력 반사 | search, q, query, keyword | 높음 |
| HTML attribute context | `<input value="...">` | 높음 |
| JavaScript string context | `var q = "..."` | 높음 |
| rich text/editor | comment, bio, description | 높음 |
| URL parameter 반사 | `/search?q=test` | 중간 |
| CSP 부재 또는 약한 CSP | no CSP, unsafe-inline | 중간 |
| 필터링 흔적 | `<` 제거, quote escaping 불완전 | 중간 |
| JSON/API reflection | JSON value에 user input 반사 | 중간 |
| static asset path | `/static/app.js` only | 낮음 |
| login-only page | password input only | 낮음 |

### 4-2. XSS 컨텍스트 분류

`xss_agent`는 payload planning 전에 injection context를 아래 중 하나로 분류한다.

| Context | 설명 | 대표 신호 |
| --- | --- | --- |
| `html_body` | HTML body에 직접 반사 | `Search results for q` |
| `html_attribute` | attribute value 안에 반사 | `value="q"` |
| `js_string` | JavaScript 문자열 안에 반사 | `var q = "q"` |
| `js_block` | JavaScript 코드 블록에 반사 | `<script>...q...</script>` |
| `url_param` | URL query/path 기반 입력 | `/search?q=` |
| `json_value` | JSON string value에 반사 | `{"query":"q"}` |
| `xml_node` | XML/SVG node에 반사 | `<svg><text>q</text></svg>` |
| `unknown` | 충분한 evidence 없음 | DOM/response 부족 |

### 4-3. 실행하지 않아야 하는 경우

`should_run=false` 조건:

- sitemap에 입력 표면이 없고 response 반사 evidence도 없다.
- 대상 URL이 정적 파일 또는 이미지/폰트/바이너리로 보인다.
- 페이지가 login form만 있고 별도 reflected field가 없다.
- router confidence가 낮고 다른 플러그인이 명확히 우선한다.
- 이전 XSS scan이 동일 endpoint/context에서 충분히 수행됐다.

---

## 5. 입출력 계약

### 5-1. Task A: XSS selection

입력:

```json
{
  "url": "/search?q=test",
  "dom": "<input name='q' type='text' value='test'>",
  "sitemap_summary": "3 forms, reflected query parameter, no file inputs",
  "response_snippet": "Search results for test"
}
```

모델 출력:

```json
{
  "plugin": "xss",
  "confidence": 92,
  "reason": "query parameter is reflected into an HTML input value"
}
```

### 5-2. Task B: XSS payload planning

입력:

```json
{
  "plugin": "xss",
  "parameter": "q",
  "injection_context": "html_attribute",
  "dom_snippet": "<input name='q' value='test'>",
  "response_snippet": "<input name='q' value='test'>",
  "previous_attempts": []
}
```

모델 출력:

```json
{
  "payloads": [
    "\"><img src=x onerror=alert(1)>",
    "'><svg/onload=alert(1)>",
    "\"><svg/onload=alert(document.domain)>"
  ],
  "bypass_variants": [
    "%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E",
    "&#34;&#62;&#60;svg/onload=alert(1)&#62;"
  ],
  "strategy": "break out of attribute value, then use event-handler execution",
  "context_notes": "attribute context requires quote close before tag injection"
}
```

### 5-3. Task C: XSS false positive filter

입력:

```json
{
  "finding": "Possible XSS",
  "evidence": "<svg/onload=alert(1)> reflected",
  "response_body": "Search results: <svg/onload=alert(1)>"
}
```

모델 출력:

```json
{
  "verdict": "confirmed",
  "reason": "payload is reflected in executable HTML context",
  "confidence": 91
}
```

### 5-4. Task D: XSS next action

입력:

```json
{
  "completed": ["xss"],
  "findings": [{"plugin": "xss", "severity": "HIGH", "title": "Reflected XSS"}],
  "sitemap": "state-changing forms and admin route discovered"
}
```

모델 출력:

```json
{
  "next_action": "csrf",
  "reason": "confirmed XSS plus state-changing forms raises CSRF/session abuse risk",
  "priority": "medium"
}
```

---

## 6. XSSAgentDecision envelope

Task A-D 결과는 아래 envelope로 조합한다. 이 envelope는 모델 원시 출력이 아니라 orchestrator 계층이 만든다.

```json
{
  "agent": "xss_agent",
  "plugin": "xss",
  "model": "s2n-agent-xss",
  "should_run": true,
  "confidence": 92,
  "reason": "query parameter is reflected into an HTML attribute context",
  "context": {
    "url": "/search?q=test",
    "parameter": "q",
    "injection_context": "html_attribute",
    "endpoint_fingerprint": "GET /search?q"
  },
  "task_outputs": {
    "selection": {
      "plugin": "xss",
      "confidence": 92,
      "reason": "query parameter is reflected into an HTML input value"
    },
    "payload_plan": {
      "payloads": ["\"><img src=x onerror=alert(1)>"],
      "bypass_variants": ["%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E"],
      "strategy": "attribute breakout",
      "context_notes": "close quote before tag injection"
    },
    "false_positive": null,
    "next_plan": null
  },
  "next_action": "run_plugin",
  "metadata": {
    "agent_decision_version": "v1",
    "source": "plugin_agent_registry",
    "latency_budget_ms": 1500
  }
}
```

저장 위치:

- `scan_context.session_data["agent_state"]["plugin_agent_decisions"]`
- `scan_context.session_data["agent_state"]["payload_plan"]`
- `PluginResult.metadata["agent_decision"]`

---

## 7. 구현 설계

### 7-1. 클래스 스케치

```python
class XSSAgent:
    agent_id = "xss_agent"
    plugin = "xss"
    model = "s2n-agent-xss"

    def evaluate_target(self, *, url, dom, sitemap_summary, response_snippet=""):
        selection = self.selection_task.run(
            url=url,
            dom=dom,
            sitemap_summary=sitemap_summary,
        )
        context = self.infer_context(url=url, dom=dom, response_snippet=response_snippet)
        should_run = selection["plugin"] == "xss" and selection["confidence"] >= 70
        return self.build_decision(selection, context, should_run)

    def plan_payloads(self, *, parameter, context, dom_snippet="", response_snippet=""):
        return self.payload_task.run(
            plugin="xss",
            parameter=parameter,
            context=context,
            dom_snippet=dom_snippet,
            response_snippet=response_snippet,
        )

    def filter_false_positive(self, *, finding, evidence, response_body):
        return self.fp_task.run(
            finding=finding,
            evidence=evidence,
            response_body=response_body,
        )

    def plan_next_action(self, *, completed, findings, sitemap):
        return self.plan_task.run(
            completed=completed,
            findings=findings,
            sitemap=sitemap,
        )
```

### 7-2. Context inference 휴리스틱

우선순위:

1. DOM/response에 `<script`가 있고 입력값이 문자열로 들어가면 `js_string` 또는 `js_block`
2. 입력값이 `value=`, `href=`, `src=`, `title=`, `data-*=` 내부에 있으면 `html_attribute`
3. 입력값이 태그 밖 텍스트로 반사되면 `html_body`
4. response가 JSON이고 값으로 반사되면 `json_value`
5. URL query만 있고 response evidence가 없으면 `url_param`
6. 확정 불가면 `unknown`

### 7-3. Parameter extraction 휴리스틱

우선순위:

1. DOM input `name`
2. URL query key
3. form field name
4. sitemap attack point parameter
5. fallback: `q`

### 7-4. Confidence 계산

`selection.confidence`를 기본값으로 사용하고, 아래 신호로 보정한다.

| 조건 | 조정 |
| --- | --- |
| response에 입력값 반사 확인 | +10 |
| `html_attribute` 또는 `js_string` 확정 | +8 |
| form field와 URL parameter가 일치 | +5 |
| CSP가 강하게 설정됨 | -10 |
| 이전 동일 endpoint/context 스캔 완료 | -20 |
| context가 `unknown` | -15 |

최종 confidence는 0-100으로 clamp한다.

---

## 8. Prompt 설계

### 8-1. System prompt

```text
You are XSSAgent, the dedicated S2N-Agent model for Cross-Site Scripting scan decisions.
Return strict JSON only.
You do not send HTTP requests, manage cookies, execute JavaScript, or parse full DOM trees.
Your job is to decide whether the S2N xss plugin should run, plan context-aware payloads,
filter false positives, and suggest the next scan action.
Prefer precise evidence-based decisions over broad speculation.
```

### 8-2. Selection user prompt

```text
Decide whether the xss plugin is the best candidate for this web context:
{input_json}
```

### 8-3. Payload planning user prompt

```text
Generate XSS payloads for the provided injection context.
Use payloads appropriate for the context and avoid repeating previous attempts:
{input_json}
```

### 8-4. False positive user prompt

```text
Decide whether this XSS finding is confirmed or likely false positive:
{input_json}
```

---

## 9. 학습 데이터 설계

### 9-1. Raw record

```json
{
  "plugin": "xss",
  "agent": "xss_agent",
  "task": "payload_planning",
  "context": {
    "url": "/search?q=test",
    "method": "GET",
    "parameter": "q",
    "injection_context": "html_attribute",
    "dom": "<input name='q' value='test'>",
    "sitemap_summary": "search form reflects q"
  },
  "evidence": {
    "response_snippet": "<input name='q' value='test'>",
    "csp": "",
    "previous_attempts": []
  },
  "expected_json": {
    "payloads": ["\"><img src=x onerror=alert(1)>"],
    "bypass_variants": ["%22%3E%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E"],
    "strategy": "attribute breakout",
    "context_notes": "close quote before injecting an event handler"
  }
}
```

### 9-2. ChatML 변환

```json
{
  "messages": [
    {
      "role": "system",
      "content": "You are XSSAgent..."
    },
    {
      "role": "user",
      "content": "Generate XSS payloads for the provided injection context:\n{\"plugin\":\"xss\",...}"
    },
    {
      "role": "assistant",
      "content": "{\"payloads\":[\"...\"],\"bypass_variants\":[\"...\"],\"strategy\":\"...\",\"context_notes\":\"...\"}"
    }
  ]
}
```

### 9-3. 데이터 비율

| Task | 수량 목표 | 설명 |
| --- | --- | --- |
| Selection | 800 | XSS 실행/비실행 판별 |
| Payload Planning | 1,000 | 컨텍스트별 payload 우선순위 |
| False Positive | 800 | reflected, escaped, inert context 구분 |
| Multi-step | 300 | XSS 이후 CSRF/JWT/path traversal 등 후속 판단 |
| Negative / hard cases | 400 | SQLi/upload/path traversal과 혼동되는 케이스 |
| 합계 | 3,300+ | v1 XSS adapter 기준 |

### 9-4. 컨텍스트별 최소 샘플

| Context | 최소 수량 |
| --- | --- |
| `html_body` | 250 |
| `html_attribute` | 250 |
| `js_string` | 200 |
| `js_block` | 120 |
| `url_param` | 120 |
| `json_value` | 120 |
| `xml_node` | 80 |
| `unknown` | 100 |

### 9-5. Negative samples

XSS가 아닌 케이스도 반드시 포함한다.

| 케이스 | 기대 출력 |
| --- | --- |
| `/profile?id=1` + DB error | `sqlinjection` 또는 `should_run=false` |
| `/upload` + file input | `file_upload` 또는 `should_run=false` |
| `/login` + password field only | `brute_force` 또는 `should_run=false` |
| `/download?file=a.pdf` + file read evidence | `path_traversal` 또는 `should_run=false` |
| escaped output `&lt;script&gt;` only | `likely_false_positive` |

---

## 10. Payload planning 정책

Payload는 S2N xss plugin이 실제 전송/검증한다. `xss_agent`는 후보를 정렬하고 컨텍스트 주석을 제공한다.

### 10-1. 컨텍스트별 payload군

| Context | 우선 payload군 |
| --- | --- |
| `html_body` | tag injection, SVG event handler |
| `html_attribute` | quote breakout + event handler |
| `js_string` | string breakout + statement terminator |
| `js_block` | expression-safe probe |
| `url_param` | reflected HTML probe, encoded variants |
| `json_value` | escaped JSON string breakout 후보 |
| `xml_node` | SVG/XML node 기반 probe |
| `unknown` | 낮은 위험의 reflection probe 우선 |

### 10-2. 제외 규칙

- 동일 endpoint/context에서 이미 실패한 payload는 후순위로 보낸다.
- context와 맞지 않는 payload를 상위 후보로 두지 않는다.
- response가 HTML escaped만 보여주면 실행형 payload보다 reflection 확인 payload를 우선한다.
- CSP가 강하면 inline script 계열을 낮추고 event handler 우회 가능성만 낮은 confidence로 제안한다.

---

## 11. False positive 판단

### 11-1. Confirmed 신호

- payload가 HTML body/attribute/script context에 unescaped로 반사됨
- evidence가 browser execution 또는 alert/callback 검증을 포함함
- sanitizer가 일부 문자만 제거해 실행 가능한 구조가 남음
- stored/reflected location이 명확함

### 11-2. Likely false positive 신호

- payload가 `&lt;`, `&gt;`, `&quot;`로 완전히 escape됨
- response body에 payload가 없음
- payload가 HTML comment, textarea text, code block 등 inert context에만 있음
- CSP 또는 sanitizer evidence가 실행을 명확히 차단함
- evidence가 request payload만 있고 response reflection이 없음

### 11-3. FP 출력 예

```json
{
  "verdict": "likely_false_positive",
  "reason": "payload appears only as escaped text and no executable context is present",
  "confidence": 86
}
```

---

## 12. 후속 액션 계획

XSS 확인 후 다음 플러그인 제안 규칙:

| 조건 | next_action | 이유 |
| --- | --- | --- |
| state-changing forms 존재 | `csrf` | XSS와 CSRF surface가 함께 있으면 세션 기반 조작 가능성 증가 |
| admin route 발견 | `path_traversal` | 관리자 기능 주변 파일 접근 surface 확인 |
| JWT auth endpoint 존재 | `jwt` | 토큰 저장/탈취 가능성이 JWT 검증 이슈와 연결될 수 있음 |
| file upload form 존재 | `file_upload` | XSS로 업로드 UI 접근 후 파일 검증 필요 |
| 모든 주요 surface 완료 | `stop` | 중복 스캔 방지 |

---

## 13. 평가 기준

| 지표 | 목표 | 측정 방식 |
| --- | --- | --- |
| XSS selection accuracy | 88%+ | XSS 실행 대상/비대상 분류 |
| `should_run` F1 | 87%+ | positive/negative 균형 세트 |
| Context classification accuracy | 85%+ | `html_body`, `html_attribute`, `js_string` 등 |
| Payload valid rate | 75%+ | S2N xss plugin이 사용할 수 있는 payload 비율 |
| Payload top-3 hit rate | 70%+ | 정답 payload군이 상위 3개 안에 포함 |
| FP verdict accuracy | 85%+ | confirmed/likely_false_positive 일치 |
| JSON parse success | 98%+ | strict JSON 파싱 성공 |
| Latency | p95 1.5s 이하 | Ollama local inference 기준 |

---

## 14. 테스트 계획

### 14-1. Unit tests

- `XSSAgent.infer_context()`가 DOM/response snippet별 context를 올바르게 분류하는지 확인
- `XSSAgent.build_decision()`이 confidence 보정을 안정적으로 수행하는지 확인
- registry에서 `"xss"`가 `xss_agent`와 `s2n-agent-xss`로 매핑되는지 확인
- Task A-D parser가 기존 출력 JSON과 호환되는지 확인

### 14-2. Dataset tests

- XSS train/valid/test split이 task와 context별로 균형인지 확인
- assistant message가 모두 JSON parse 가능한지 확인
- `plugin == "xss"` positive와 negative sample이 모두 있는지 확인
- payload planning sample에 `strategy`, `context_notes`가 빠지지 않는지 확인

### 14-3. Integration tests

- `assist` 모드에서 `xss_agent` 결정이 로그와 `agent_state`에만 남고 실행 목록은 바꾸지 않는지 확인
- `smart` 모드에서 router top-k에 XSS가 포함될 때만 `xss_agent`가 호출되는지 확인
- `should_run=false`이면 XSS plugin 실행 후보에서 제외되는지 확인
- `on_finding`에서 XSS finding만 XSS FP 경로로 들어가는지 확인
- `post_scan`에서 `PluginResult.metadata["agent_decision"]`이 기록되는지 확인

---

## 15. 구현 단계

### Phase 1. 문서/계약 확정

- `docs/plugins/xss.md` 확정
- `PluginAgentDecision` envelope 타입 정의
- XSS context enum 정의

### Phase 2. Agent skeleton

- `s2nagent/plugin_agents/base.py`
- `s2nagent/plugin_agents/xss.py`
- `s2nagent/plugin_agents/registry.py`
- `S2NAgentPlugin.pre_scan`에서 registry 호출

### Phase 3. Dataset

- `data/plugin_agents/xss/raw.jsonl` 원천 포맷 생성
- ChatML 변환 스크립트 추가
- context별 샘플 균형 검증

### Phase 4. Model

- `s2nagent/models/Modelfile.xss` 생성
- `lora-out/xss` 학습
- `ollama create s2n-agent-xss -f s2nagent/models/Modelfile.xss`
- `scripts/evaluate.py`에 plugin-agent 평가 모드 추가

### Phase 5. Integration

- `assist` 모드 기록 검증
- `smart` 모드 실행 후보 제한 검증
- `aggressive` 모드 next_action 반복 제한 검증
- benchmark report에 XSS 전담 지표 추가

---

## 16. 완료 조건

- `xss_agent`가 registry에 등록된다.
- `s2n-agent-xss` 모델명이 Ollama에서 호출 가능하다.
- Task A-D 원시 출력 JSON이 기존 parser와 호환된다.
- `XSSAgentDecision` envelope가 `agent_state`와 `PluginResult.metadata`에 기록된다.
- XSS selection accuracy 88%+, FP verdict accuracy 85%+, JSON parse success 98%+를 만족한다.
- `assist` 모드는 실행을 바꾸지 않고, `smart` 모드는 `should_run`을 실행 후보 제한에 사용한다.
