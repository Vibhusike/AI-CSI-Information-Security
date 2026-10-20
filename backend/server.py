from __future__ import annotations

from functools import lru_cache
from typing import Literal

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from ml import ModelBundle
from pipeline import analyse


class ArtifactInput(BaseModel):
    id: str
    name: str
    type: Literal[
        "endpoint_auth", "firewall", "ids", "email_headers", "dns", "browser_history", "sysmon",
        "memory", "edr", "proxy", "pcap", "registry", "unknown",
    ] = "unknown"
    text: str
    sha256: str = Field(min_length=64, max_length=64, pattern=r"^[a-fA-F0-9]{64}$")
    size: int = 0
    ingestedAt: str = ""


class AnalysisRequest(BaseModel):
    caseId: str = Field(min_length=4, max_length=64)
    artifacts: list[ArtifactInput] = Field(max_length=50)


app = FastAPI(title="AI-CSI Review 2 Analysis Service", version="2.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


@lru_cache(maxsize=1)
def get_models() -> ModelBundle:
    return ModelBundle()


@app.get("/api/health")
def health() -> dict[str, str | bool]:
    return {"ok": True, "service": "AI-CSI analysis", "modelsReady": bool(get_models())}


@app.post("/api/analyse")
def analyse_case(request: AnalysisRequest) -> dict:
    try:
        return analyse(request.caseId, [artifact.model_dump() for artifact in request.artifacts], get_models())
    except (ValueError, RuntimeError) as error:
        raise HTTPException(status_code=422, detail=str(error)) from error
