"""Replay inert Equifax-pattern lab logs through the existing AI-CSI pipeline.

This is a capability test, not Equifax telemetry or a reconstruction benchmark.
No exploit payload, personal data, or outbound network request is included.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

from forensic import build_review3
from ml import ModelBundle
from pipeline import analyse


ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "public" / "sample-data" / "review3"
FILES = [
    ("equifax_pattern_proxy.csv", "proxy"),
    ("equifax_pattern_sysmon.csv", "sysmon"),
    ("equifax_pattern_auth.csv", "endpoint_auth"),
    ("equifax_pattern_firewall.csv", "firewall"),
    ("equifax_pattern_pcap.json", "pcap"),
]


def artifact(name: str, evidence_type: str) -> dict:
    content = (SAMPLES / name).read_text(encoding="utf-8")
    return {
        "id": f"lab-{name}", "name": name, "type": evidence_type, "text": content,
        "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
        "size": len(content.encode("utf-8")), "ingestedAt": "2026-01-12T10:20:00Z",
    }


def summarize(label: str, files: list[dict], models: ModelBundle) -> dict:
    analysis = analyse(f"ACSI-REVIEW3-{label.upper()}", files, models)
    report = build_review3(analysis)
    valid_hashes = {item["sha256"] for item in analysis["artifacts"]}
    sections = ("summary", "story", "detections", "mitre", "shap", "missingEvidence", "inventory")
    claims = [claim for section in sections for claim in report[section]]
    if not all(claim["citations"] and all(ref["sha256"] in valid_hashes for ref in claim["citations"]) for claim in claims):
        raise AssertionError("A report claim lacks a verified source reference")
    return {
        "artifacts": [{"name": item["name"], "type": item["type"], "sha256": item["sha256"],
                       "rows": item["rowCount"], "provenance": item["provenanceScore"]} for item in analysis["artifacts"]],
        "events": [{"time": event["timestamp"], "eventType": event["eventType"],
                    "sourceFile": event["sourceFile"], "classification": event["classification"],
                    "winningClassProbability": event["classificationProbability"],
                    "mappedTechniques": [item["techniqueId"] for item in event["mitre"]]} for event in analysis["events"]],
        "caseHypothesis": analysis["hypothesis"]["title"],
        "mappedTechniques": [item["techniqueId"] for item in analysis["mitre"]],
        "graphNodes": len(analysis["graph"]["nodes"]), "graphEdges": len(analysis["graph"]["edges"]),
        "confidence": analysis["confidence"],
        "topMissingEvidence": [item["label"] for item in analysis["recommendations"][:5]],
        "citedClaimCount": len(claims), "allClaimsCitedToVerifiedHashes": True,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "docs" / "review3_case_study_results.json")
    args = parser.parse_args()
    # The replay is local and deterministic; do not transmit lab evidence to an LLM.
    os.environ["AICSI_ENABLE_NER"] = "0"
    os.environ["AICSI_LLM_PROVIDER"] = "disabled"
    files = [artifact(name, evidence_type) for name, evidence_type in FILES]
    models = ModelBundle()
    tampered = dict(files[0], text=files[0]["text"] + "\n2026-01-12T10:30:00Z,forged_event\n")
    try:
        analyse("ACSI-REVIEW3-TAMPER", [tampered], models)
        tamper_result = "unexpectedly accepted"
    except ValueError as error:
        tamper_result = str(error)
    result = {
        "notice": "Inert synthetic Equifax-pattern lab logs, not historical Equifax evidence. Times and hosts are invented for testing.",
        "model": "Existing saved three-class AI-CSI XGBoost model; no retraining",
        "tamperedEvidenceResult": tamper_result,
        "stages": {
            "web_proxy_only": summarize("web-only", files[:1], models),
            "four_source_replay": summarize("four-source", files[:4], models),
            "with_pcap_metadata": summarize("pcap-added", files, models),
        },
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(args.output), "stages": {name: {"events": len(stage["events"]),
          "techniques": stage["mappedTechniques"], "confidence": stage["confidence"]["overall"]}
          for name, stage in result["stages"].items()}}, indent=2))


if __name__ == "__main__":
    main()
