# S2N-Agent 파인튜닝 모델 개발 계획서

> **기준 문서** — S2N-Agent 전체 모델 개발 방향과 S2N 통합 전략.
> 최종 검증: 2026-05-06
>
> 주의: `s2n/s2nscanner/...` 경로는 외부 S2N 패키지의 참조 구조이며, 이 repo의 직접 구현 대상은 `s2nagent/...`입니다.

---

## 1. 프로젝트 개요

S2N은 플러그인 기반 웹 취약점 스캐너입니다.

```
Crawler → SiteMap 생성 → Plugin 실행 → ScanReport
```

현재 실행 흐름:

| 단계          | 파일                                  | 핵심                 |
| ------------- | ------------------------------------- | -------------------- |
| CLI 진입      | `s2n/s2nscanner/cli/runner.py`        | Click CLI            |
| 플러그인 탐색 | `s2n/s2nscanner/plugins/discovery.py` | `discover_plugins()` |
| 스캔 실행     | `s2n/s2nscanner/scan_engine.py`       | `Scanner.scan()`     |
| 인터페이스    | `s2n/s2nscanner/interfaces.py`        | 모든 타입 정의       |

**S2N-Agent 목표**: 기존 결정론적 스캔에 LLM 의사결정 레이어 추가.

```
기존: URL/DOM → 조건 충족 → Plugin 실행
목표: URL/DOM/SiteMap/응답 → Router Agent → Plugin Agent → Plugin 실행 → 결과 해석
```

---

## 2. 현재 플러그인 목록 (12개, 2026-05-06 기준)

```
s2n/s2nscanner/plugins/
  autobot/         brute_force/     csrf/           file_upload/
  jwt/             oscommand/       path_traversal/ react2shell/
  sensitive_files/ soft_brute_force/ sqlinjection/  xss/
```

ATT&CK 매핑 (mitre-attack-plugin-guide.md §2 참조):

| Plugin                         | TID       | Tactic            |
| ------------------------------ | --------- | ----------------- |
| xss                            | T1059.007 | Execution         |
| sqlinjection                   | T1190     | Initial Access    |
| oscommand                      | T1059     | Execution         |
| csrf                           | T1185     | Collection        |
| file_upload                    | T1505.003 | Persistence       |
| brute_force / soft_brute_force | T1110     | Credential Access |
| jwt                            | T1528     | Credential Access |
| autobot                        | T1190     | Initial Access    |
| path_traversal                 | T1083     | Discovery         |
| sensitive_files                | T1552.001 | Credential Access |
| react2shell                    | T1505.003 | Persistence       |

---

## 3. S2N-Agent 핵심 원칙

```
모델 = 사고 / 판단 / 계획
플러그인 = 실제 공격 실행
```

모델이 하는 것:

- 어떤 플러그인을 실행할지 결정
- 어떤 payload를 쓸지 결정
- 결과 해석
- 다음 단계 판단

모델이 하지 않는 것:

- HTTP 요청 직접 전송
- 세션/쿠키 관리
- DOM 파싱 직접 처리

모델 운영 기준:

- `RouterAgent`: 전체 SiteMap/DOM/응답을 보고 실행 후보 플러그인 top-k를 고른다.
- `PluginAgent`: 각 플러그인별 전담 모델 또는 전담 프롬프트로 `should_run`, payload, 결과 해석을 판단한다.
- `S2NAgentPlugin`: router와 plugin agent 결과를 `ScanContext.session_data["agent_state"]`와 `PluginResult.metadata["agent_decision"]`에 기록한다.
- S2N core plugin: 실제 스캔, HTTP 요청, 세션/쿠키, 검증을 담당한다.

플러그인별 모델 분리 방식은 `docs/plugin-plan.md`를 기준으로 한다. v1 권장안은 12개 풀 모델이 아니라 **공통 베이스 모델 + 플러그인별 LoRA/QLoRA 어댑터 + router**다.

---

## 4. 통합 포인트 (외부 S2N 참조 구조)

### 4-1. `ScannerConfig`에 `ai_mode` 추가

**파일**: `s2n/s2nscanner/interfaces.py:113`

```python
@dataclass(frozen=True)
class ScannerConfig:
    crawl_depth: int = 2
    max_threads: int = 5
    timeout: int = 30
    max_retries: int = 3
    retry_delay: float = 1.0
    user_agent: str = "S2N-Scanner/0.1.0"
    follow_redirects: bool = True
    verify_ssl: bool = True
    # 추가 대상:
    ai_mode: str = "off"          # off | assist | smart | aggressive
    ai_model: str = "s2n-agent"   # Ollama 모델명
    ai_endpoint: str = "http://localhost:11434"
```

### 4-2. 플러그인 생명주기 훅 (이미 존재)

**파일**: `s2n/s2nscanner/scan_engine.py:464-512`

```
pre_scan(plugin_context)   → 스캔 전 AI context 주입 가능
run(plugin_context)        → 실제 스캔
post_scan(plugin_context)  → 결과 해석 + 다음 액션 계획
cleanup(plugin_context)    → 정리
```

`S2NAgentPlugin`은 `pre_scan`에서 SiteMap을 읽어 router 후보와 플러그인별 agent 결정을 만들고, `run`은 assist 모드 권고를 출력하며, `post_scan`에서 결과를 해석해 다음 스캔 계획을 반환하는 구조로 설계한다.

### 4-3. `on_finding` 실시간 콜백 (이미 존재)

**파일**: `s2n/s2nscanner/scan_engine.py:71`

```python
Scanner(
    config=scan_config,
    on_finding=lambda f: agent.analyze_finding(f),  # AI 실시간 피드백
)
```

### 4-4. `ScanContext.session_data` — AI 상태 저장

**파일**: `s2n/s2nscanner/interfaces.py:207`

```python
scan_context.session_data["agent_state"] = {
    "plan": [...],
    "plugin_agent_decisions": [...],
    "completed_plugins": [...],
    "next_actions": [...],
}
```

### 4-5. `scan_context.sitemap` — 크롤 결과 접근

**파일**: `s2n/s2nscanner/scan_engine.py:174-179`

`smart_crawl()` 결과가 `scan_context.sitemap`에 자동 첨부됨. Agent는 이를 읽어 공격면을 추론.

```python
sitemap = getattr(plugin_context.scan_context, "sitemap", None)
pages = sitemap.pages if sitemap else []
```

### 4-6. `PluginResult.metadata` — AI 결정 기록

**파일**: `s2n/s2nscanner/interfaces.py:291`

```python
PluginResult(
    ...,
    metadata={
        "agent_decision": {
            "agent": "xss_agent",
            "plugin": "xss",
            "model": "s2n-agent-xss",
            "should_run": True,
            "confidence": 91,
        },
        "payloads_tried": 12,
        "reasoning": "input[name=q] detected — XSS likely",
    }
)
```

### 4-7. CLI 플러그인 목록 — 동적 탐색 (이미 업데이트됨)

**파일**: `s2n/s2nscanner/cli/runner.py:153-154`

```python
# 현재 코드 (하드코딩 아님 — discover_plugins() 동적 방식)
if run_all or not plugin_list:
    plugin_list = [p["id"] for p in discover_plugins()]
```

새 플러그인 추가 시 `runner.py` 수정 불필요. `__init__.py`에 `Plugin` export만 있으면 자동 포함됨.

---

## 5. 모델 학습 태스크 정의

현재 `s2nagent/tasks/`와 `scripts/evaluate.py`가 기대하는 Task A-D 출력 JSON은 유지한다. 플러그인별 전담 agent의 공통 envelope는 모델의 원시 출력이 아니라 orchestration 계층에서 조합해 저장한다.

공통 envelope 예:

```json
{
  "agent": "xss_agent",
  "plugin": "xss",
  "model": "s2n-agent-xss",
  "should_run": true,
  "confidence": 91,
  "reason": "reflected input in html_attribute context",
  "task_outputs": {
    "selection": {"plugin": "xss", "confidence": 91, "reason": "..."},
    "payload_plan": {"payloads": ["<svg/onload=alert(1)>"], "strategy": "..."},
    "false_positive": null,
    "next_plan": null
  },
  "next_action": "run_plugin"
}
```

### Task A. Plugin Selection

```json
{
  "input": {
    "url": "/search?q=test",
    "dom": "<input name='q' type='text'>",
    "sitemap_summary": "3 forms, 1 file input, 0 login forms"
  },
  "output": {"plugin": "xss", "confidence": 91}
}
```

### Task B. Payload Planning

```json
{
  "input": {"plugin": "xss", "parameter": "q", "context": "html_attribute"},
  "output": {
    "payloads": ["<svg/onload=alert(1)>", "\"><img src=x onerror=alert(1)>"]
  }
}
```

### Task C. False Positive Filter

```json
{
  "input": {
    "finding": "Possible SQLi",
    "evidence": "error: near syntax",
    "response_body": "Welcome to our site"
  },
  "output": {"verdict": "likely_false_positive", "reason": "error not in response"}
}
```

### Task D. Multi-step Planner

```json
{
  "input": {
    "completed": ["xss", "csrf"],
    "findings": [{"plugin": "jwt", "severity": "HIGH"}],
    "sitemap": "admin route /admin/panel discovered"
  },
  "output": {
    "next_action": "path_traversal",
    "reason": "admin route suggests privileged file access possible"
  }
}
```

---

## 6. 데이터셋 구성

최종 학습 파일은 현재 구현과 같은 ChatML JSONL을 유지한다.

```json
{
  "messages": [
    {"role": "system", "content": "plugin-specific system prompt"},
    {"role": "user", "content": "task input JSON"},
    {"role": "assistant", "content": "task output strict JSON"}
  ]
}
```

플러그인별 모델 학습을 위해 내부 원천 데이터에는 `plugin`, `agent`, `task`, `context`, `evidence`, `expected_json` 필드를 둔다.

| 유형 | 대상 | 수량 목표 |
| --- | --- | --- |
| Router | 12개 플러그인 후보 선정 | 1,200 |
| P0 adapters | XSS, SQLi, Upload, JWT | 플러그인당 600-1,000 |
| P1 profiles/adapters | OS Command, Path Traversal, Sensitive Files, React2Shell | 플러그인당 300-600 |
| P2 profiles | CSRF, Brute Force, Soft Brute Force, Autobot | 플러그인당 200-400 |
| False Positive 사례 | plugin별 confirmed/FP 균형 | 1,200+ |

데이터 소스: DVWA, Juice Shop, WebGoat, 직접 생성 샘플

---

## 7. 모델 운영 전략

| 용도 | 모델/방식 | 이유 |
| --- | --- | --- |
| Router | Qwen2.5-Coder 3B 또는 7B | 후보 top-k 선정은 빠른 응답이 중요 |
| P0 Plugin Agent | Qwen2.5-Coder 7B + plugin LoRA/QLoRA | XSS/SQLi/Upload/JWT는 전문성 필요 |
| P1 Plugin Agent | 공통 7B + prompt profile, 이후 adapter | 데이터 확보 후 분리 |
| P2 Plugin Agent | 공통 7B + prompt profile | 초기 운영 비용 최소화 |
| 보고서 보조 | Gemma 계열 등 별도 자연어 모델 | strict JSON 판단 모델과 분리 가능 |

---

## 8. 파인튜닝 방식

- **방법**: LoRA / QLoRA
- **도구**: MLX-LM (Apple Silicon), PEFT, Transformers
- **운영**: 낮 = 개발/추론, 밤 = 파인튜닝

권장 모델 크기: 3B (빠름), 7B (최적). 14B 이상 로컬 학습 비권장.

v1 학습 순서:

1. `s2n-agent-router`
2. `s2n-agent-xss`
3. `s2n-agent-sqli`
4. `s2n-agent-upload`
5. `s2n-agent-jwt`

나머지 8개 플러그인은 v1에서 공통 모델 + plugin-specific system prompt로 운영하고, 평가 지표가 부족한 순서대로 adapter를 추가한다.

---

## 9. Ollama 배포

```dockerfile
# Modelfile
FROM qwen2.5-coder:7b
ADAPTER ./s2n-lora
SYSTEM """
You are S2N-Agent. Return strict JSON only.
You optimize web vulnerability scanning workflows.
Select plugins, plan payloads, interpret results, plan next actions.
"""
```

```bash
ollama create s2n-agent -f s2nagent/models/Modelfile
ollama create s2n-agent-xss -f s2nagent/models/Modelfile.xss
ollama create s2n-agent-sqli -f s2nagent/models/Modelfile.sqli
```

`Modelfile.xss`, `Modelfile.sqli`처럼 플러그인별 Modelfile은 신규 생성 대상이다. 초기에는 공통 `s2nagent/models/Modelfile`을 복제한 뒤 adapter와 system prompt만 분리한다.

---

## 10. S2N 통합 구조 (확정된 훅 기반)

```
Scanner.scan()
  ↓ smart_crawl() → scan_context.sitemap 자동 첨부
  ↓ S2NAgentPlugin.pre_scan(ctx)
      ↓ RouterAgent: 후보 플러그인 top-k 선정
      ↓ PluginAgent: 후보별 should_run + payload 계획
      ↓ agent_state["plugin_agent_decisions"] 저장
  ↓ selected S2N plugins run(ctx)  ← 실제 스캔
  ↓ on_finding(finding)            ← 실시간 AI 피드백 가능
  ↓ S2NAgentPlugin.post_scan(ctx)
      ↓ FP 필터 + 다음 액션 계획
      ↓ PluginResult.metadata["agent_decision"] 기록
  ↓ ScanReport 반환
```

`assist` 모드에서는 실행 플러그인을 바꾸지 않고 권고만 남긴다. `smart` 모드부터 router와 `should_run` 결과를 사용해 실행 후보를 제한한다.

---

## 11. CLI UX 설계

```bash
s2n scan -u https://target.com --ai-mode off        # 기본 (현재)
s2n scan -u https://target.com --ai-mode assist     # AI 권고만 (실행은 기존)
s2n scan -u https://target.com --ai-mode smart      # router + plugin agent가 실행 후보 선택
s2n scan -u https://target.com --ai-mode aggressive # plugin agent 기반 멀티스텝 계획
```

`--ai-mode` 옵션 추가 위치: `s2n/s2nscanner/cli/runner.py` scan 명령어 (`@click.option` 블록)

---

## 12. 평가 지표

| 항목                   | 목표 |
| ---------------------- | ---- |
| Plugin 선택 정확도     | 85%+ |
| Router top-3 recall    | 95%+ |
| Plugin should_run F1   | 85%+ |
| False Positive 감소    | 30%+ |
| JSON 파싱 성공률       | 95%+ |
| 평균 탐색 시간 단축    | 20%+ |
| Hidden Endpoint 탐지율 | 증가 |

---

## 13. 개발 일정

| 주차   | 작업 |
| ------ | ---- |
| Week 1 | `PluginAgentDecision` envelope / registry 설계 / Task A-D 호환성 유지 |
| Week 2 | Router + P0 agent skeleton (`xss`, `sqlinjection`, `file_upload`, `jwt`) |
| Week 3 | P0 adapter 학습 / plugin별 JSONL 생성 / `on_finding` 실시간 피드백 연결 |
| Week 4 | Ollama 모델명 분리 / CLI `--ai-mode`, `--ai-model`, `--ai-endpoint` 공개 |
| Week 5+ | P1/P2 플러그인 adapter 확장 및 benchmark |

---

## 14. Claude Code Skill 프롬프트 예시

### 구조 설계

```
s2n/s2nscanner/interfaces.py:113 ScannerConfig에 ai_mode, ai_model, ai_endpoint 필드 추가.
s2n/s2nscanner/scan_engine.py:71 Scanner.__init__에 ai_agent 파라미터 추가.
pre_scan/post_scan 훅(scan_engine.py:466-512)을 통해 RouterAgent + PluginAgent registry 호출 구조 설계해줘.
```

### 데이터 생성

```
XSS 전담 agent 학습용 ChatML JSONL 500개 생성.
원천 필드: {plugin, agent, task, context, evidence, expected_json}
최종 출력: messages[{system,user,assistant}]
interfaces.py:246 Finding 구조 참고.
```

### 코드 작성

```
s2nagent/plugin_agents/registry.py에 12개 플러그인 agent registry 스켈레톤 추가.
S2NAgentPlugin.pre_scan에서 router top-k와 PluginAgentDecision envelope를 agent_state에 저장.
```

### 평가

```
Router top-3 recall, Plugin should_run F1, Task C FP 감소율 benchmark 코드 작성.
interfaces.py:246 Finding, interfaces.py:280 PluginResult 기반.
```

---

## 15. 핵심 성공 전략

```
LLM이 스캐너를 대체하면 실패한다.
LLM이 스캐너를 지휘하면 성공한다.
```

최종 권장 실행 순서:

1. Router를 3B 또는 7B로 먼저 실험
2. P0 플러그인 4개를 개별 adapter로 분리
3. 공통 envelope와 registry를 S2NAgentPlugin에 통합
4. Ollama에 `s2n-agent-*` 모델명으로 배포
5. P1/P2 플러그인은 평가 지표에 따라 adapter로 승격
