"""
HuggingFace Transformers 클라이언트 (로컬 추론).

`pip install s2n-agent[huggingface]` 설치 시 사용 가능합니다.
Apple Silicon에서는 MPS 백엔드를 자동으로 선택합니다.
"""

from __future__ import annotations

import json
import logging
from typing import Any

logger = logging.getLogger("s2nagent.hf")

_SYSTEM_PROMPT = (
    "You are S2N-Agent. Return strict JSON only. "
    "You optimize web vulnerability scanning workflows. "
    "Select plugins, plan payloads, interpret results, plan next actions."
)


class HuggingFaceClient:
    """
    로컬 HuggingFace 모델 추론 클라이언트.

    모델은 처음 호출 시 지연 로드됩니다.
    """

    def __init__(
        self,
        repo_id: str = "s2n-agent/qwen2.5-coder-7b-s2n",
        device: str | None = None,
        load_in_4bit: bool = True,
        max_new_tokens: int = 512,
    ) -> None:
        self.repo_id = repo_id
        self.device = device  # None → 자동 선택
        self.load_in_4bit = load_in_4bit
        self.max_new_tokens = max_new_tokens
        self._pipeline: Any = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(self, prompt: str, *, system: str | None = None) -> dict[str, Any]:
        """
        프롬프트를 모델에 전달하고 JSON 응답을 반환합니다.

        Raises:
            ImportError: transformers/torch 미설치 시
            HuggingFaceError: 추론 또는 JSON 파싱 실패 시
        """
        pipe = self._get_pipeline()
        messages = [
            {"role": "system", "content": system or _SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ]
        outputs = pipe(messages, max_new_tokens=self.max_new_tokens, return_full_text=False)
        raw: str = outputs[0]["generated_text"].strip()

        # JSON 블록 추출 (```json ... ``` 형식 대응)
        if "```" in raw:
            raw = raw.split("```")[-2].lstrip("json").strip()

        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise HuggingFaceError(f"Model returned non-JSON: {raw[:200]}") from exc

    def is_available(self) -> bool:
        """transformers/torch 패키지가 설치되어 있는지 확인합니다."""
        try:
            import transformers  # noqa: F401
            import torch  # noqa: F401
            return True
        except ImportError:
            return False

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _get_pipeline(self) -> Any:
        if self._pipeline is not None:
            return self._pipeline

        try:
            import torch
            from transformers import pipeline, BitsAndBytesConfig
        except ImportError as exc:
            raise ImportError(
                "HuggingFace 추론을 사용하려면 `pip install s2n-agent[huggingface]`를 실행하세요."
            ) from exc

        device = self._resolve_device(torch)
        logger.info("모델 로드 중: %s (device=%s)", self.repo_id, device)

        kwargs: dict[str, Any] = {
            "model": self.repo_id,
            "task": "text-generation",
            "trust_remote_code": True,
        }

        if self.load_in_4bit and device != "mps":
            # MPS는 bitsandbytes 미지원 — CPU/CUDA에서만 4-bit 양자화
            kwargs["model_kwargs"] = {
                "quantization_config": BitsAndBytesConfig(load_in_4bit=True)
            }
        else:
            kwargs["device"] = device

        self._pipeline = pipeline(**kwargs)
        return self._pipeline

    def _resolve_device(self, torch: Any) -> str:
        if self.device:
            return self.device
        if torch.backends.mps.is_available():
            return "mps"
        if torch.cuda.is_available():
            return "cuda"
        return "cpu"


class HuggingFaceError(RuntimeError):
    """HuggingFace 추론 실패 시 발생."""
