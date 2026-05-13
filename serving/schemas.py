from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class XSSAgentRequest(BaseModel):
    task: str = Field(..., description="selection | payload_planning | false_positive | next_action")
    url: str
    method: str = "GET"
    parameters: List[str] = Field(default_factory=list)
    response_sample: Optional[str] = None
    evidence: Dict[str, Any] = Field(default_factory=dict)


class XSSAgentResponse(BaseModel):
    task: str
    should_run: Optional[bool] = None
    context_known: Optional[bool] = None
    confidence: float = 0.0
    reason: str
    raw_output: Optional[str] = None
    fallback: bool = False


class NormalizedFinding(BaseModel):
    finding_id: str
    vuln_type: str
    url: str
    method: str
    parameter: Optional[str] = None
    payload: Optional[str] = None
    evidence: Dict[str, Any] = Field(default_factory=dict)
    agent_judgement: Dict[str, Any] = Field(default_factory=dict)
    severity: str = "unknown"
    next_action: str = "review"
