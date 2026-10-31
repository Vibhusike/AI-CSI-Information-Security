from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import forensic
import server
from ml import ModelBundle
from pipeline import analyse


ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def investigation():
    source = ROOT / "public/sample-data/review2/phishing_endpoint_auth.csv"
    text = source.read_text()
    artifact = {"id": "auth-1", "name": source.name, "type": "endpoint_auth", "text": text,
                "sha256": hashlib.sha256(text.encode()).hexdigest(), "size": len(text), "ingestedAt": "2026-09-23T00:00:00Z"}
    return analyse("ACSI-REVIEW3-TEST", [artifact], ModelBundle())


def test_cited_report_and_chronology(investigation, monkeypatch):
    monkeypatch.setenv("AICSI_LLM_PROVIDER", "disabled")
    report = forensic.build_review3(investigation)
    assert report["story"]
    assert [claim["id"] for claim in report["story"]] == [f"E{i}" for i in range(1, len(investigation["events"]) + 1)]
    assert all(claim["citations"] and all(ref["sha256"] == investigation["artifacts"][0]["sha256"] for ref in claim["citations"])
               for section in ("summary", "story", "detections", "mitre", "shap", "missingEvidence", "inventory") for claim in report[section])
    assert all(claim["kind"] == "observed" for claim in report["story"])
    assert report["inventory"][0]["citations"][0]["sha256"] == investigation["artifacts"][0]["sha256"]


def test_llm_hallucinated_text_and_unknown_references_are_discarded(investigation, monkeypatch):
    class FakeResponse:
        def raise_for_status(self): pass
        def json(self): return {"message": {"content": '{"ids":["D1","FAKE-REFERENCE"],"finding":"A made-up attacker stole data"}'}}
    monkeypatch.setenv("AICSI_LLM_PROVIDER", "ollama")
    monkeypatch.setattr(forensic.httpx, "post", lambda *args, **kwargs: FakeResponse())
    report = forensic.build_review3(investigation)
    rendered = " ".join(claim["text"] for claim in report["summary"])
    assert "made-up attacker" not in rendered
    assert all(claim["id"] != "FAKE-REFERENCE" for claim in report["summary"])
    assert report["llmStatus"] == "ready"


def test_failed_llm_and_unsupported_question(investigation, monkeypatch):
    def fail(*args, **kwargs):
        raise forensic.httpx.ConnectError("offline")
    monkeypatch.setenv("AICSI_LLM_PROVIDER", "ollama")
    monkeypatch.setattr(forensic.httpx, "post", fail)
    report = forensic.build_review3(investigation)
    assert report["summary"] and "fallback" in report["generationMethod"]
    answer = forensic.answer_question(investigation, "quasar nebula spacecraft")
    assert not answer["claims"]
    assert "does not support" in answer["answer"]
    supported = forensic.answer_question(investigation, "Which login event was suspicious?")
    assert supported["claims"]
    assert all(claim["citations"] for claim in supported["claims"])


def test_api_rejects_stale_hash_and_pdf_has_citations(investigation, monkeypatch):
    monkeypatch.setenv("AICSI_LLM_PROVIDER", "disabled")
    server.investigations[investigation["caseId"]] = investigation
    client = TestClient(server.app)
    payload = {"caseId": investigation["caseId"], "artifactHashes": [investigation["artifacts"][0]["sha256"]]}
    assert client.post("/api/review3/report", json={**payload, "artifactHashes": ["0" * 64]}).status_code == 409
    response = client.post("/api/review3/report", json=payload)
    assert response.status_code == 200
    assert response.json()["inventory"][0]["citations"]
    pdf = client.post("/api/review3/pdf", json=payload)
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")
    assert len(pdf.content) > 3000


def test_openai_responses_key_and_structured_claim_selection(investigation, monkeypatch):
    seen = {}
    class FakeResponse:
        def raise_for_status(self): pass
        def json(self): return {"output": [{"type": "message", "content": [{"type": "output_text", "text": '{"ids":["D1"]}'}]}]}
    def fake_post(url, **kwargs):
        seen.update({"url": url, **kwargs})
        return FakeResponse()
    monkeypatch.setenv("AICSI_LLM_PROVIDER", "openai")
    monkeypatch.setenv("OPENAI_API_KEY", "test-only-key")
    monkeypatch.delenv("AICSI_LLM_MODEL", raising=False)
    monkeypatch.setattr(forensic.httpx, "post", fake_post)
    report = forensic.build_review3(investigation)
    assert report["llmStatus"] == "ready"
    assert [claim["id"] for claim in report["summary"]] == ["D1"]
    assert seen["url"] == "https://api.openai.com/v1/responses"
    assert seen["headers"]["Authorization"] == "Bearer test-only-key"
    assert seen["json"]["store"] is False
    assert seen["json"]["text"]["format"]["schema"]["properties"]["ids"]["items"]["enum"]


def test_openai_missing_key_falls_back(investigation, monkeypatch):
    monkeypatch.setenv("AICSI_LLM_PROVIDER", "openai")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.setattr(forensic, "dotenv_values", lambda _: {})
    report = forensic.build_review3(investigation)
    assert report["summary"]
    assert report["llmStatus"] == "OpenAI key missing"


def test_openai_reads_key_added_after_start(investigation, monkeypatch):
    captured = {}
    class FakeResponse:
        def raise_for_status(self): pass
        def json(self): return {"output": [{"type": "message", "content": [{"type": "output_text", "text": '{"ids":["D1"]}'}]}]}
    def fake_post(url, **kwargs):
        captured.update(kwargs)
        return FakeResponse()
    monkeypatch.setenv("AICSI_LLM_PROVIDER", "openai")
    monkeypatch.setenv("OPENAI_API_KEY", "")
    monkeypatch.setattr(forensic, "dotenv_values", lambda _: {"OPENAI_API_KEY": "test-file-key"})
    monkeypatch.setattr(forensic.httpx, "post", fake_post)
    assert forensic.build_review3(investigation)["llmStatus"] == "ready"
    assert captured["headers"]["Authorization"] == "Bearer test-file-key"
