from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

FPVerdict = Literal["confirmed", "likely_false_positive", "inconclusive"]
Priority = Literal["high", "medium", "low"]


class PluginAgentDecision(BaseModel):
    """
    Common decision envelope for plugin-specific agents.

    task_outputs holds per-task results keyed by task name:
      - "selection"      -> SelectionOutput
      - "payload_plan"   -> PayloadPlanOutput
      - "false_positive" -> FalsePositiveOutput
      - "next_action"    -> NextActionOutput

    This schema is designed to be reused by future agents such as:
    - XSSAgent
    - SQLInjectionAgent
    - CSRFAgent
    - JWTAgent
    """

    agent: str
    plugin: str
    model: str

    should_run: bool
    confidence: int = Field(ge=0, le=100)
    reason: str

    context: dict[str, Any] = Field(default_factory=dict)
    task_outputs: dict[str, Any] = Field(default_factory=dict)

    next_action: str
    metadata: dict[str, Any] = Field(default_factory=dict)


class SelectionOutput(BaseModel):
    plugin: str
    should_run: bool
    confidence: int = Field(ge=0, le=100)
    reason: str


class PayloadPlanOutput(BaseModel):
    payloads: list[str]
    bypass_variants: list[str] = []
    strategy: str
    context_notes: str


class FalsePositiveOutput(BaseModel):
    verdict: FPVerdict
    reason: str
    confidence: int = Field(ge=0, le=100)


class NextActionOutput(BaseModel):
    next_action: str
    reason: str
    priority: Priority
