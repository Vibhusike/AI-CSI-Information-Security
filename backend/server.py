from __future__ import annotations

from functools import lru_cache
import re
from pathlib import Path
from threading import Lock
from typing import Literal

from fastapi import FastAPI, HTTPException
from fastapi.responses import Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from dotenv import load_dotenv

load_dotenv(Path(__file__).with_name(".env"), override=False)

from ml import ModelBundle
from pipeline import analyse
from forensic import answer_question, build_review3, render_pdf


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


class CaseRequest(BaseModel):
    caseId: str
    artifactHashes: list[str] = Field(max_length=50)


class QuestionRequest(CaseRequest):
    question: str = Field(min_length=3, max_length=500)


app = FastAPI(title="AI-CSI Review 3 Analysis Service", version="3.0.0")
investigations: dict[str, dict] = {}
generated_reports: dict[str, dict] = {}
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


_models_lock = Lock()


@lru_cache(maxsize=1)
def _load_models() -> ModelBundle:
    return ModelBundle()


def get_models() -> ModelBundle:
    # lru_cache alone can call the loader more than once under concurrent requests.
    with _models_lock:
        return _load_models()


@app.get("/api/health")
def health() -> dict[str, str | bool]:
    return {"ok": True, "service": "AI-CSI analysis", "modelsReady": bool(get_models())}


@app.post("/api/analyse")
def analyse_case(request: AnalysisRequest) -> dict:
    try:
        result = analyse(request.caseId, [artifact.model_dump() for artifact in request.artifacts], get_models())
        investigations[request.caseId] = result
        generated_reports.pop(request.caseId, None)
        return result
    except (ValueError, RuntimeError) as error:
        raise HTTPException(status_code=422, detail=str(error)) from error


def verified_case(request: CaseRequest) -> dict:
    result = investigations.get(request.caseId)
    if result is None:
        raise HTTPException(status_code=404, detail="Analyse this case before requesting Review 3 features.")
    actual = [item["sha256"] for item in result["artifacts"]]
    if actual != request.artifactHashes:
        raise HTTPException(status_code=409, detail="Evidence changed; run analysis again.")
    return result


@app.post("/api/review3/report")
def review3_report(request: CaseRequest) -> dict:
    result = verified_case(request)
    report = build_review3(result)
    generated_reports[request.caseId] = report
    return report


@app.post("/api/review3/ask")
def review3_ask(request: QuestionRequest) -> dict:
    return answer_question(verified_case(request), request.question)


@app.post("/api/review3/pdf")
def review3_pdf(request: CaseRequest) -> Response:
    result = verified_case(request)
    report = generated_reports.get(request.caseId) or build_review3(result)
    safe_case_id = re.sub(r"[^A-Za-z0-9_-]", "_", request.caseId)[:64]
    return Response(render_pdf(report), media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{safe_case_id}-forensic-report.pdf"'})
