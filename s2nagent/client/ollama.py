"""
Ollama API 클라이언트.

로컬 Ollama 서버와 통신하여 s2n-agent 모델을 호출합니다.
응답은 항상 JSON으로 파싱됩니다 (모델이 strict JSON을 반환하도록 훈련됨).
"""

from __future__ import annotations

import json
import logging
from typing import Any

import httpx

logger = logging.getLogger("s2nagent.ollama")

_DEFAULT_ENDPOINT = "http://localhost:11434"
_DEFAULT_MODEL = "s2n-agent"
_GENERATE_PATH = "/api/generate"
_TAGS_PATH = "/api/tags"


class OllamaClient:
    """Ollama /api/generate 엔드포인트 래퍼."""

    def __init__(
        self,
        endpoint: str = _DEFAULT_ENDPOINT,
        model: str = _DEFAULT_MODEL,
        timeout: float = 60.0,
    ) -> None:
        self.endpoint = endpoint.rstrip("/")
        self.model = model
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(self, prompt: str, *, system: str | None = None) -> dict[str, Any]:
        """
        단일 프롬프트를 모델에 전달하고 JSON 응답을 반환합니다.

        Returns:
            파싱된 JSON dict

        Raises:
            OllamaError: 서버 오류 또는 JSON 파싱 실패 시
        """
        payload: dict[str, Any] = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
        }
        if system:
            payload["system"] = system

        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(
                    f"{self.endpoint}{_GENERATE_PATH}",
                    json=payload,
                )
                resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise OllamaError(f"HTTP {exc.response.status_code}: {exc.response.text}") from exc
        except httpx.RequestError as exc:
            raise OllamaError(f"Connection failed ({self.endpoint}): {exc}") from exc

        raw = resp.json().get("response", "")
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise OllamaError(f"Model returned non-JSON: {raw[:200]}") from exc

    def is_available(self) -> bool:
        """Ollama 서버와 지정 모델이 준비되었는지 확인합니다."""
        try:
            with httpx.Client(timeout=5.0) as client:
                resp = client.get(f"{self.endpoint}{_TAGS_PATH}")
                resp.raise_for_status()
                models = [m["name"] for m in resp.json().get("models", [])]
                # 모델명은 "s2n-agent:latest" 형식일 수 있음
                return any(m.startswith(self.model) for m in models)
        except Exception:
            return False


class OllamaError(RuntimeError):
    """Ollama 호출 실패 시 발생."""
