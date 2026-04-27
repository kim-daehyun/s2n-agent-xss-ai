"""
학습 데이터 JSONL 스키마 정의 (Tasks A-D).

각 샘플은 {"messages": [...]} 형식의 ChatML 포맷으로 저장됩니다.
Qwen2.5-Coder / 대부분의 instruction-tuned 모델과 호환됩니다.
"""

from __future__ import annotations

from typing import Any


def make_sample(system: str, user: str, assistant: str) -> dict[str, Any]:
    """ChatML 포맷 단일 샘플 생성."""
    return {
        "messages": [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
            {"role": "assistant", "content": assistant},
        ]
    }


# ── Task A ──────────────────────────────────────────────────────────────────

TASK_A_SYSTEM = (
    "You are S2N-Agent, a web vulnerability scanner AI. "
    "Analyze the given web context and select the single most relevant security plugin. "
    "Return ONLY a JSON object: {\"plugin\": \"<name>\", \"confidence\": <0-100>, \"reason\": \"<brief>\"}."
)

# ── Task B ──────────────────────────────────────────────────────────────────

TASK_B_SYSTEM = (
    "You are S2N-Agent. Given a vulnerability plugin and injection context, "
    "generate a prioritized list of test payloads. "
    "Return ONLY a JSON object: {\"payloads\": [\"...\", ...], \"strategy\": \"<brief description>\"}. "
    "Maximum 10 payloads."
)

# ── Task C ──────────────────────────────────────────────────────────────────

TASK_C_SYSTEM = (
    "You are S2N-Agent. Analyze a vulnerability finding and determine if it is a "
    "real vulnerability or a false positive. "
    "Return ONLY a JSON object: "
    "{\"verdict\": \"confirmed|likely_false_positive\", \"reason\": \"<brief>\", \"confidence\": <0-100>}."
)

# ── Task D ──────────────────────────────────────────────────────────────────

TASK_D_SYSTEM = (
    "You are S2N-Agent. Given the completed plugins, current findings, and sitemap, "
    "decide the next best action to maximize vulnerability discovery. "
    "Return ONLY a JSON object: "
    "{\"next_action\": \"<plugin_name|stop>\", \"reason\": \"<brief>\", \"priority\": \"high|medium|low\"}."
)
