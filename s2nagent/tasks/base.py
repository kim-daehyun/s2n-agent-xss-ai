"""Task 기반 클래스 — 모든 LLM 태스크가 상속."""

from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from typing import Any

logger = logging.getLogger("s2nagent.task")


class BaseTask(ABC):
    """LLM 태스크 기반 클래스."""

    #: 모델에 전달할 시스템 프롬프트 (서브클래스에서 오버라이드)
    SYSTEM_PROMPT: str = (
        "You are S2N-Agent. Return strict JSON only. "
        "You optimize web vulnerability scanning workflows."
    )

    def __init__(self, client: Any) -> None:
        """
        Args:
            client: OllamaClient 또는 HuggingFaceClient 인스턴스
        """
        self.client = client

    @abstractmethod
    def build_prompt(self, **kwargs: Any) -> str:
        """태스크별 프롬프트 생성."""

    @abstractmethod
    def parse_response(self, response: dict[str, Any]) -> Any:
        """모델 응답 파싱 및 검증."""

    def run(self, **kwargs: Any) -> Any:
        """프롬프트 생성 → LLM 호출 → 응답 파싱."""
        prompt = self.build_prompt(**kwargs)
        logger.debug("Task %s prompt: %s", self.__class__.__name__, prompt[:200])
        response = self.client.generate(prompt, system=self.SYSTEM_PROMPT)
        result = self.parse_response(response)
        logger.debug("Task %s result: %s", self.__class__.__name__, json.dumps(result, default=str)[:200])
        return result
