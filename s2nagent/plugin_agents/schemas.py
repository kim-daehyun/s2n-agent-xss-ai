from __future__ import annotations

from typing import Any, Optional
from pydantic import BaseModel, Field


class PluginAgentDecision(BaseModel):
    """
    공통 Plugin Agent 판단 결과 envelope.
    향후 SQLiAgent, CSRFAgent, JWTAgent도 이 구조를 재사용한다.
    """

    agent: str
    plugin: str
    model: str

    should_run: bool
    confidence: int = Field(ge=0, le=100)
    reason: str

    context: dict[str, Any]
    task_outputs: dict[str, Any]

    next_action: str
    metadata: dict[str, Any]


class SelectionOutput(BaseModel):
    plugin: str
    should_run: Optional[bool] = None
    confidence: int = Field(ge=0, le=100)
    reason: str


class PayloadPlanOutput(BaseModel):
    payloads: list[str]
    bypass_variants: list[str] = []
    strategy: str
    context_notes: str


class FalsePositiveOutput(BaseModel):
    verdict: str
    reason: str
    confidence: int = Field(ge=0, le=100)


class NextActionOutput(BaseModel):
    next_action: str
    reason: str
    priority: str