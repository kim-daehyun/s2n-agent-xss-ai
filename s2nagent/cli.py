"""
s2n-agent CLI — 독립 실행 커맨드라인 인터페이스.

사용법:
    s2n-agent select  --url "/search?q=test" --dom "<input name=q>"
    s2n-agent plan    --plugin xss --parameter q --context html_body
    s2n-agent filter  --finding "Possible SQLi" --evidence "error: near syntax"
    s2n-agent next    --completed xss,csrf --finding '{"plugin":"jwt","severity":"HIGH"}'
    s2n-agent deploy  --adapter lora-out/3b
    s2n-agent smoke
"""

from __future__ import annotations

import json
import logging
import sys
from typing import Any

import click

_LOG_FORMAT = "%(levelname)s  %(message)s"


def _build_agent(endpoint: str, model: str, mode: str) -> Any:
    from s2nagent.agent import S2NAgent
    return S2NAgent(endpoint=endpoint, model=model, mode=mode)


def _print_json(data: dict) -> None:
    click.echo(json.dumps(data, ensure_ascii=False, indent=2))


# ── 공통 옵션 ─────────────────────────────────────────────────────────────────

_common = [
    click.option("--endpoint", default="http://localhost:11434", show_default=True,
                 help="Ollama 서버 주소"),
    click.option("--model", default="s2n-agent", show_default=True,
                 help="Ollama 모델명"),
    click.option("--mode", default="smart", show_default=True,
                 type=click.Choice(["off", "assist", "smart", "aggressive"]),
                 help="AI 모드"),
    click.option("--verbose", "-v", is_flag=True, help="디버그 로그 출력"),
]


def common_options(f):
    for opt in reversed(_common):
        f = opt(f)
    return f


# ── CLI 그룹 ──────────────────────────────────────────────────────────────────

@click.group()
@click.version_option(package_name="s2n-agent")
def cli() -> None:
    """S2N-Agent: LLM 기반 웹 취약점 스캐너 의사결정 레이어."""


# ── select ────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--url", required=True, help="대상 URL (예: /search?q=test)")
@click.option("--dom", default="", help="HTML DOM 스니펫")
@click.option("--sitemap", default="", help="사이트맵 요약 문자열")
@common_options
def select(url: str, dom: str, sitemap: str, endpoint: str, model: str, mode: str, verbose: bool) -> None:
    """Task A: 최적 플러그인 선택."""
    _configure_logging(verbose)
    agent = _build_agent(endpoint, model, mode)
    result = agent.select_plugin(url=url, dom=dom, sitemap_summary=sitemap)
    _print_json(result)


# ── plan ──────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--plugin", required=True, help="플러그인명 (예: xss)")
@click.option("--parameter", default="q", show_default=True, help="파라미터명")
@click.option("--context", default="html_body", show_default=True,
              type=click.Choice([
                  "html_body", "html_attribute", "js_string",
                  "sql_string", "sql_numeric", "url_param",
                  "shell_arg", "path_segment", "http_header",
              ]),
              help="injection context")
@click.option("--dom", default="", help="DOM 스니펫 (선택)")
@click.option("--response", default="", help="응답 스니펫 (선택)")
@common_options
def plan(
    plugin: str, parameter: str, context: str,
    dom: str, response: str,
    endpoint: str, model: str, mode: str, verbose: bool,
) -> None:
    """Task B: payload 목록 + bypass 변형 생성."""
    _configure_logging(verbose)
    agent = _build_agent(endpoint, model, mode)
    result = agent.plan_payloads(
        plugin=plugin,
        parameter=parameter,
        context=context,
        dom_snippet=dom,
        response_snippet=response,
    )
    _print_json(result)


# ── filter ────────────────────────────────────────────────────────────────────

@cli.command(name="filter")
@click.option("--finding", required=True, help="finding 제목")
@click.option("--evidence", default="", help="증거 문자열")
@click.option("--response-body", default="", help="HTTP 응답 본문 (일부)")
@common_options
def filter_cmd(
    finding: str, evidence: str, response_body: str,
    endpoint: str, model: str, mode: str, verbose: bool,
) -> None:
    """Task C: False Positive 판별."""
    _configure_logging(verbose)
    agent = _build_agent(endpoint, model, mode)
    result = agent.filter_false_positive(
        finding=finding, evidence=evidence, response_body=response_body
    )
    _print_json(result)


# ── next ──────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--completed", default="", help="완료된 플러그인 목록 (쉼표 구분, 예: xss,csrf)")
@click.option("--finding", "findings_json", multiple=True,
              help="finding JSON (반복 가능, 예: '{\"plugin\":\"jwt\",\"severity\":\"HIGH\"}')")
@click.option("--sitemap", default="", help="사이트맵 요약")
@common_options
def next(
    completed: str, findings_json: tuple[str, ...], sitemap: str,
    endpoint: str, model: str, mode: str, verbose: bool,
) -> None:
    """Task D: 다음 스캔 액션 계획."""
    _configure_logging(verbose)
    agent = _build_agent(endpoint, model, mode)

    completed_list = [p.strip() for p in completed.split(",") if p.strip()]
    findings: list[dict] = []
    for raw in findings_json:
        try:
            findings.append(json.loads(raw))
        except json.JSONDecodeError as e:
            click.echo(f"[경고] finding JSON 파싱 실패: {e}", err=True)

    result = agent.plan_next_action(
        completed=completed_list,
        findings=findings,
        sitemap=sitemap,
    )
    _print_json(result)


# ── smoke ─────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--endpoint", default="http://localhost:11434", show_default=True)
@click.option("--model", default="s2n-agent", show_default=True)
def smoke(endpoint: str, model: str) -> None:
    """배포 후 4가지 태스크 빠른 검증."""
    import importlib.util
    from pathlib import Path
    smoke_path = Path(__file__).parent.parent / "scripts" / "smoke_test.py"
    spec = importlib.util.spec_from_file_location("smoke_test", smoke_path)
    if spec is None:
        click.echo("[오류] scripts/smoke_test.py 를 찾을 수 없습니다.", err=True)
        sys.exit(1)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    ok = mod.run_smoke(endpoint=endpoint, model=model)
    sys.exit(0 if ok else 1)


# ── deploy ────────────────────────────────────────────────────────────────────

@cli.command()
@click.option("--adapter", default="none", show_default=True,
              help="LoRA adapter 경로 또는 'none' (base 모델만)")
def deploy(adapter: str) -> None:
    """Ollama에 s2n-agent 모델 배포 (scripts/deploy_ollama.sh 래퍼)."""
    import subprocess
    from pathlib import Path
    script = Path(__file__).parent.parent / "scripts" / "deploy_ollama.sh"
    result = subprocess.run(["bash", str(script), adapter], check=False)
    sys.exit(result.returncode)


# ── 내부 유틸 ─────────────────────────────────────────────────────────────────

def _configure_logging(verbose: bool) -> None:
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(level=level, format=_LOG_FORMAT)


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
