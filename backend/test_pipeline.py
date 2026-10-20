from __future__ import annotations

import hashlib
import os
from pathlib import Path

import pytest

from ml import ModelBundle
from pipeline import analyse, detect_evidence_type, deterministic_entities, parse_rows


ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "public" / "sample-data" / "review2"
os.environ["AICSI_ENABLE_NER"] = "0"


@pytest.fixture(scope="session")
def models() -> ModelBundle:
    return ModelBundle()


def artifact(filename: str, evidence_type: str = "unknown") -> dict:
    text = (SAMPLES / filename).read_text()
    return {
        "id": f"artifact-{filename}",
        "name": filename,
        "type": evidence_type,
        "text": text,
        "sha256": hashlib.sha256(text.encode()).hexdigest(),
        "size": len(text.encode()),
        "ingestedAt": "2026-09-23T00:00:00Z",
    }


def phishing_initial() -> list[dict]:
    return [
        artifact("phishing_endpoint_auth.csv", "endpoint_auth"),
        artifact("phishing_firewall.csv", "firewall"),
        artifact("phishing_ids.jsonl", "ids"),
    ]


def test_parsing_detection_and_deterministic_iocs() -> None:
    text = (SAMPLES / "phishing_dns.csv").read_text()
    rows = parse_rows(text, "phishing_dns.csv")
    assert len(rows) == 2
    assert detect_evidence_type("uploaded-evidence.csv", text) == "dns"
    entities = deterministic_entities({
        "src_ip": "10.24.8.19", "dst_ip": "198.51.100.77", "domain": "login.example",
        "url": "https://login.example/path", "host": "WS-19", "user": "riya", "process": "browser.exe",
        "parent_process": "explorer.exe", "resource": "", "message": "Event ID 4624 over TCP/443",
    })
    kinds = {item["type"] for item in entities}
    assert {"ip", "domain", "url", "user", "host", "process", "port", "event_id"} <= kinds


def test_full_real_pipeline_and_confidence_formula(models: ModelBundle) -> None:
    uploaded = phishing_initial()
    result = analyse("ACSI-2026-TEST", uploaded, models)
    assert result["events"]
    assert result["hypothesis"]["id"] == "phishing_credential_compromise"
    assert result["system"]["distilbert"]["status"] == "REAL"
    assert result["system"]["xgboost"]["status"] == "REAL"
    assert result["graph"]["engine"].startswith("NetworkX")
    assert result["mitre"]
    assert all(event["shap"] for event in result["events"])
    assert result["artifacts"][0]["sha256"] == hashlib.sha256(
        uploaded[0]["text"].encode()
    ).hexdigest()
    confidence = result["confidence"]
    expected = 100 * (
        0.35 * confidence["evidenceCoverage"] + 0.25 * confidence["modelConfidence"]
        + 0.25 * confidence["temporalCoherence"] + 0.15 * confidence["provenanceIntegrity"]
    )
    assert confidence["overall"] == pytest.approx(expected, abs=0.1)
    assert confidence["provenanceIntegrity"] == 1


def test_email_first_and_dns_first_are_different(models: ModelBundle) -> None:
    initial = phishing_initial()
    email_first = analyse("ACSI-2026-EMAIL", initial + [artifact("phishing_email_headers.json", "email_headers")], models)
    dns_first = analyse("ACSI-2026-DNS", initial + [artifact("phishing_dns.csv", "dns")], models)
    assert email_first["confidence"]["evidenceCoverage"] != dns_first["confidence"]["evidenceCoverage"]
    assert email_first["confidence"]["overall"] != dns_first["confidence"]["overall"]
    assert [item["type"] for item in email_first["recommendations"]] != [item["type"] for item in dns_first["recommendations"]]


def test_unrelated_evidence_does_not_progress_a_scripted_state(models: ModelBundle) -> None:
    initial = phishing_initial()
    before = analyse("ACSI-2026-BASE", initial, models)
    text = "timestamp,event_type,status,message\n2026-09-12T10:00:00Z,service_health,success,Routine printer health check\n"
    unrelated = {
        "id": "unrelated", "name": "printer-health.csv", "type": "unknown", "text": text,
        "sha256": hashlib.sha256(text.encode()).hexdigest(), "size": len(text), "ingestedAt": "2026-09-23T00:00:00Z",
    }
    after = analyse("ACSI-2026-BASE", initial + [unrelated], models)
    assert before["confidence"]["evidenceCoverage"] == after["confidence"]["evidenceCoverage"]
    assert [item["type"] for item in before["recommendations"]] == [item["type"] for item in after["recommendations"]]


def test_manual_new_investigation_and_hash_mismatch(models: ModelBundle) -> None:
    text = (ROOT / "public" / "sample_security_logs.csv").read_text()
    uploaded = {"id": "manual", "name": "my-upload.csv", "type": "unknown", "text": text, "sha256": "0" * 64, "size": len(text), "ingestedAt": "2026-09-23T00:00:00Z"}
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        analyse("ACSI-2026-MANUAL", [uploaded], models)
    uploaded["sha256"] = ""
    with pytest.raises(ValueError, match="SHA-256 missing"):
        analyse("ACSI-2026-MANUAL", [uploaded], models)
    uploaded["sha256"] = hashlib.sha256(text.encode()).hexdigest()
    result = analyse("ACSI-2026-MANUAL", [uploaded], models)
    assert result["events"]
    assert result["artifacts"][0]["provenanceChecks"]["hashMatchesClient"] is True


def test_real_transformer_ner(models: ModelBundle) -> None:
    entities = models.semantic_entities(["Alice from Microsoft opened the security console in London."])[0]
    assert entities
    assert all(item["extractor"] for item in entities)
