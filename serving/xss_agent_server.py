from fastapi import FastAPI
from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional

from serving.model_loader import XSSAgentModel


app = FastAPI(
    title="XSSAgent FastAPI Inference Server",
    version="0.1.0",
)


class XSSAgentRequest(BaseModel):
    task: str
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


model = None


@app.on_event("startup")
def startup_event():
    global model
    model = XSSAgentModel()


@app.get("/")
def root():
    return {
        "status": "ok",
        "message": "XSSAgent FastAPI server is running.",
        "endpoints": ["/health", "/predict", "/predict/xss", "/docs"],
    }


@app.get("/health")
def health():
    return {
        "status": "ok",
        "model_loaded": model is not None,
    }


def run_prediction(req: XSSAgentRequest) -> XSSAgentResponse:
    try:
        payload = req.model_dump()

        result = model.generate(payload)

        return XSSAgentResponse(
            task=result.get("task", req.task),
            should_run=result.get("should_run"),
            context_known=result.get("context_known"),
            confidence=float(result.get("confidence", 0.0)),
            reason=result.get("reason", ""),
            raw_output=result.get("raw_output"),
            fallback=False,
        )

    except Exception as e:
        return XSSAgentResponse(
            task=req.task,
            should_run=False,
            context_known=False,
            confidence=0.0,
            reason=f"Model inference or JSON parsing failed: {e}",
            raw_output=None,
            fallback=True,
        )


@app.post("/predict", response_model=XSSAgentResponse)
def predict(req: XSSAgentRequest):
    return run_prediction(req)


@app.post("/predict/xss", response_model=XSSAgentResponse)
def predict_xss(req: XSSAgentRequest):
    return run_prediction(req)
