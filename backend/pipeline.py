from __future__ import annotations

import csv
import hashlib
import io
import ipaddress
import json
import os
import re
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import networkx as nx
import numpy as np

from ml import EMBEDDING_MODEL, NER_MODEL, ModelBundle


ROOT = Path(__file__).resolve().parent.parent
ATTACK = json.loads((ROOT / "backend" / "data" / "mitre_attack_subset.json").read_text())
MODEL_METADATA = json.loads((ROOT / "models" / "metadata.json").read_text()) if (ROOT / "models" / "metadata.json").exists() else {}

ALIASES = {
    "timestamp": ["timestamp", "time", "datetime", "date", "@timestamp"],
    "host": ["host", "hostname", "computer", "device", "asset"],
    "user": ["user", "username", "account", "principal", "subject_user_name"],
    "process": ["process", "process_name", "image", "application"],
    "parent_process": ["parent_process", "parent_image", "parentprocess"],
    "src_ip": ["source_ip", "sourceip", "src_ip", "srcip", "ip", "client_ip"],
    "dst_ip": ["destination_ip", "dest_ip", "dst_ip", "server_ip"],
    "domain": ["domain", "query", "dns_name", "host_name"],
    "url": ["url", "uri", "request_url"],
    "event_type": ["event_type", "eventtype", "event", "action", "activity", "signature"],
    "status": ["status", "result", "outcome", "verdict"],
    "resource": ["resource", "target", "file", "path", "destination"],
    "message": ["details", "message", "description", "notes", "raw_message"],
    "event_id": ["event_id", "eventid", "id", "record_id"],
}

EVIDENCE_LABELS = {
    "endpoint_auth": "Windows / authentication logs", "firewall": "Firewall logs", "ids": "IDS alerts",
    "email_headers": "Email headers", "dns": "DNS query logs", "browser_history": "Browser history",
    "sysmon": "Sysmon process telemetry", "memory": "Memory capture", "edr": "Endpoint detection telemetry",
    "proxy": "Web proxy logs", "pcap": "Network packet capture", "registry": "Registry artifacts",
    "unknown": "Unclassified artifact",
}

REQUIREMENTS: dict[str, list[tuple[str, float, str]]] = {
    "T1566.002": [
        ("email_headers", 1.0, "Confirms sender path, authentication failures, and the phishing message."),
        ("browser_history", 0.8, "Links the user session to the lure and redirect chain."),
        ("dns", 0.7, "Shows resolution of the phishing landing domain."),
        ("ids", 0.55, "Corroborates malicious redirect or credential-harvesting observations."),
    ],
    "T1110": [
        ("endpoint_auth", 1.0, "Validates failures, MFA prompts, and account outcomes."),
        ("sysmon", 0.55, "Corroborates process and token activity around credential abuse."),
        ("memory", 0.45, "May recover volatile tokens or credential material."),
    ],
    "T1078": [
        ("endpoint_auth", 1.0, "Attributes suspicious access to an account and session."),
        ("firewall", 0.55, "Corroborates the source and destination of the authenticated session."),
        ("sysmon", 0.5, "Connects the account session to endpoint activity."),
    ],
    "T1114.003": [
        ("endpoint_auth", 0.7, "Shows the mailbox-rule action and responsible account."),
        ("email_headers", 0.6, "Can validate externally forwarded message paths."),
    ],
    "T1059.001": [
        ("sysmon", 1.0, "Provides PowerShell process, parent, and command-line evidence."),
        ("edr", 0.75, "Corroborates execution and endpoint detection context."),
        ("memory", 0.45, "May preserve decoded commands or injected content."),
    ],
    "T1204.002": [
        ("email_headers", 0.8, "Connects the malicious file to its delivery message."),
        ("edr", 0.8, "Shows file execution and endpoint response."),
        ("sysmon", 0.65, "Shows the child-process chain after opening the file."),
    ],
    "T1547.001": [
        ("registry", 1.0, "Validates the startup or run-key persistence change."),
        ("sysmon", 0.85, "Links the persistence value to the creating process."),
        ("memory", 0.4, "May corroborate the resident process or configuration."),
    ],
    "T1486": [
        ("edr", 1.0, "Confirms encryption behaviour and affected paths."),
        ("sysmon", 0.75, "Provides process and file-change activity."),
        ("memory", 0.55, "May recover ransomware configuration or keys."),
    ],
    "T1071.001": [
        ("firewall", 0.85, "Corroborates outbound sessions and destinations."),
        ("dns", 0.8, "Validates resolution of command-and-control infrastructure."),
        ("pcap", 0.75, "Provides flow timing and protocol-level evidence."),
        ("proxy", 0.55, "May expose request paths and web-session context."),
    ],
    "T1071.004": [
        ("dns", 1.0, "Confirms query content, frequency, and tunnelling patterns."),
        ("pcap", 0.8, "Preserves packet-level DNS evidence."),
    ],
    "T1074": [
        ("edr", 0.85, "Links collection and staging to endpoint processes."),
        ("sysmon", 0.75, "Shows file creation and process lineage."),
        ("endpoint_auth", 0.45, "Attributes staging activity to a user session."),
    ],
    "T1041": [
        ("pcap", 1.0, "Confirms transfer timing, endpoints, and byte volume."),
        ("proxy", 0.9, "Shows destination, method, user session, and upload volume."),
        ("firewall", 0.8, "Corroborates the external connection and transferred bytes."),
        ("dns", 0.6, "Validates destination resolution."),
    ],
    "T1055": [("edr", 0.9, "Corroborates process injection telemetry."), ("memory", 1.0, "Can directly validate injected code and target process.")],
    "T1562.001": [("edr", 0.9, "Shows the impaired security control and responsible process."), ("sysmon", 0.65, "Corroborates service or policy changes.")],
}

TACTIC_ORDER = [
    "Discovery", "Initial Access", "Credential Access", "Execution", "Persistence", "Privilege Escalation",
    "Collection", "Command and Control", "Exfiltration", "Defense Impairment", "Impact",
]

TRANSITIONS = {
    "Discovery": {"Initial Access", "Credential Access", "Execution"},
    "Initial Access": {"Credential Access", "Execution", "Collection"},
    "Credential Access": {"Initial Access", "Execution", "Privilege Escalation", "Collection"},
    "Execution": {"Persistence", "Privilege Escalation", "Collection", "Command and Control", "Impact"},
    "Persistence": {"Privilege Escalation", "Collection", "Command and Control", "Impact"},
    "Privilege Escalation": {"Collection", "Command and Control", "Exfiltration", "Impact"},
    "Collection": {"Command and Control", "Exfiltration", "Impact"},
    "Command and Control": {"Collection", "Exfiltration", "Impact"},
    "Exfiltration": {"Impact"},
    "Defense Impairment": {"Impact", "Collection", "Exfiltration"},
    "Impact": set(),
}


def normalise_key(value: str) -> str:
    return re.sub(r"[\s-]+", "_", value.strip().lower())


def row_value(row: dict[str, Any], field: str) -> str:
    normalized = {normalise_key(str(key)): value for key, value in row.items()}
    for alias in ALIASES[field]:
        if alias in normalized and normalized[alias] not in (None, ""):
            value = normalized[alias]
            return json.dumps(value, sort_keys=True) if isinstance(value, (dict, list)) else str(value).strip()
    return ""


def parse_rows(text: str, filename: str) -> list[dict[str, Any]]:
    clean = text.lstrip("\ufeff").strip()
    if not clean:
        return []
    if filename.lower().endswith((".jsonl", ".log")) and clean.startswith("{"):
        return [json.loads(line) for line in clean.splitlines() if line.strip()]
    if clean.startswith("["):
        parsed = json.loads(clean)
        if not isinstance(parsed, list):
            raise ValueError("JSON evidence must contain an array of events.")
        return [item for item in parsed if isinstance(item, dict)]
    if clean.startswith("{"):
        try:
            parsed = json.loads(clean)
            if isinstance(parsed, dict):
                if isinstance(parsed.get("events"), list):
                    return [item for item in parsed["events"] if isinstance(item, dict)]
                return [parsed]
        except json.JSONDecodeError:
            return [json.loads(line) for line in clean.splitlines() if line.strip()]
    if filename.lower().endswith(".txt") or (filename.lower().endswith(".log") and not clean.startswith("{")):
        rows = []
        for index, line in enumerate(clean.splitlines()):
            timestamp = re.search(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?", line)
            rows.append({"timestamp": timestamp.group(0) if timestamp else "", "event_type": "unstructured_log", "message": line, "event_id": index})
        return rows
    return list(csv.DictReader(io.StringIO(clean)))


def detect_evidence_type(filename: str, text: str, declared: str = "unknown") -> str:
    if declared and declared != "unknown":
        return declared
    value = f"{filename} {text[:5000]}".lower()
    patterns = [
        ("email_headers", r"email|header|spf|dkim|subject|reply-to"), ("dns", r"\bdns\b|dns_query|query_type"),
        ("firewall", r"firewall|src_ip.*dst_ip|egress"), ("ids", r"\bids\b|intrusion|signature|alerted"),
        ("sysmon", r"sysmon|event.?id.?1|parent_process|parent_image"), ("proxy", r"proxy|web_request|http_method"),
        ("memory", r"memory|volatile|injected"), ("registry", r"registry|hkey|run_key"),
        ("pcap", r"pcap|packet|flow metadata"), ("edr", r"\bedr\b|endpoint detection|malware|ransomware"),
        ("browser_history", r"browser|history|visited_url"), ("endpoint_auth", r"login|authentication|event.?id.?4624|oauth|mfa"),
    ]
    for evidence_type, pattern in patterns:
        if re.search(pattern, value):
            return evidence_type
    return "unknown"


def valid_timestamp(value: str) -> str | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except ValueError:
        return None


def deterministic_entities(event: dict[str, Any]) -> list[dict[str, Any]]:
    text = " ".join(str(event.get(key, "")) for key in ("src_ip", "dst_ip", "domain", "url", "host", "user", "process", "parent_process", "resource", "message"))
    entities: dict[tuple[str, str], dict[str, Any]] = {}
    def add(kind: str, value: str) -> None:
        clean = value.strip().rstrip("),.;")
        if clean:
            entities[(kind, clean.lower())] = {"type": kind, "value": clean, "confidence": 1.0, "extractor": "deterministic parser/regex"}
    for match in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text):
        try:
            ipaddress.ip_address(match); add("ip", match)
        except ValueError:
            pass
    for match in re.findall(r"\b(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64})\b", text, re.I): add("hash", match.lower())
    for match in re.findall(r"https?://[^\s,;]+", text, re.I):
        add("url", match)
        if urlparse(match).hostname: add("domain", str(urlparse(match).hostname).lower())
    for match in re.findall(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|in|example)\b", text, re.I): add("domain", match.lower())
    for match in re.findall(r"\b(?:tcp|udp)?/?\d{1,5}\b", text, re.I):
        digits = re.sub(r"\D", "", match)
        if digits and 0 < int(digits) <= 65535: add("port", digits)
    for match in re.findall(r"\bEvent\s*ID\s*[:#]?\s*(\d+)\b", text, re.I): add("event_id", match)
    for key, kind in (("user", "user"), ("host", "host"), ("process", "process"), ("parent_process", "process")):
        if event.get(key): add(kind, str(event[key]))
    return list(entities.values())


def event_text(event: dict[str, Any]) -> str:
    return " | ".join(part for part in [event.get("event_type", ""), event.get("message", ""), event.get("status", ""), event.get("resource", ""), event.get("source_type", "")] if part)


def map_mitre(event: dict[str, Any]) -> list[dict[str, str]]:
    value = f"{event.get('event_type', '')} {event.get('message', '')}".lower()
    mappings = []
    for technique in ATTACK["techniques"]:
        if any(pattern in value for pattern in technique["patterns"]):
            mappings.append({"techniqueId": technique["id"], "technique": technique["name"], "tactic": technique["tactic"]})
    return mappings


def hypothesis_from_evidence(events: list[dict[str, Any]]) -> dict[str, Any]:
    relevant = [event for event in events if event["classification"] != "NORMAL"]
    techniques = {mapping["techniqueId"] for event in relevant for mapping in event["mitre"]}
    scores = {
        "phishing_credential_compromise": len(techniques & {"T1566.002", "T1110", "T1078", "T1114.003"}),
        "malware_persistence": len(techniques & {"T1204.002", "T1059.001", "T1547.001", "T1486", "T1055", "T1562.001"}),
        "data_exfiltration": len(techniques & {"T1074", "T1041", "T1071.004", "T1071.001"}),
    }
    winner = max(scores, key=scores.get) if any(scores.values()) else "undetermined"
    titles = {
        "phishing_credential_compromise": ("Phishing-led credential compromise", "Email, authentication, or account-use evidence supports a phishing-led compromise hypothesis."),
        "malware_persistence": ("Malware execution with persistence", "Execution and endpoint evidence supports malware activity with possible persistence."),
        "data_exfiltration": ("Data staging and exfiltration", "Collection and outbound-transfer evidence supports a possible exfiltration hypothesis."),
        "undetermined": ("No supported attack hypothesis", "Current evidence does not yet support a specific attack reconstruction."),
    }
    title, summary = titles[winner]
    supporting = [event["id"] for event in relevant if event["mitre"]]
    return {"id": winner, "title": title, "summary": summary, "supportingEventIds": supporting, "techniqueVotes": scores}


def temporal_score(events: list[dict[str, Any]], correlation_edges: list[dict[str, Any]]) -> tuple[float, dict[str, Any]]:
    relevant = sorted([event for event in events if event["classification"] != "NORMAL" and event["mitre"]], key=lambda item: item["timestamp"])
    if not relevant:
        return 0.0, {"chronology": 0.0, "transitionSupport": 0.0, "entityContinuity": 0.0, "correlationDensity": 0.0, "eventsEvaluated": 0}
    chronology = 1.0
    transitions: list[float] = []
    continuity: list[float] = []
    for previous, current in zip(relevant, relevant[1:], strict=False):
        previous_tactic = previous["mitre"][0]["tactic"]
        current_tactic = current["mitre"][0]["tactic"]
        if previous_tactic == current_tactic:
            transitions.append(0.9)
        elif current_tactic in TRANSITIONS.get(previous_tactic, set()):
            transitions.append(1.0)
        else:
            previous_index = TACTIC_ORDER.index(previous_tactic) if previous_tactic in TACTIC_ORDER else -1
            current_index = TACTIC_ORDER.index(current_tactic) if current_tactic in TACTIC_ORDER else -1
            transitions.append(0.5 if current_index >= previous_index else 0.2)
        previous_entities = {(item["type"], item["value"].lower()) for item in previous["entities"]}
        current_entities = {(item["type"], item["value"].lower()) for item in current["entities"]}
        continuity.append(1.0 if previous_entities & current_entities else 0.25)
    transition_support = float(np.mean(transitions)) if transitions else 0.6
    entity_continuity = float(np.mean(continuity)) if continuity else 0.5
    correlation_density = min(1.0, len(correlation_edges) / max(1, len(relevant) - 1))
    score = 0.2 * chronology + 0.35 * transition_support + 0.3 * entity_continuity + 0.15 * correlation_density
    details = {"chronology": round(chronology, 4), "transitionSupport": round(transition_support, 4), "entityContinuity": round(entity_continuity, 4), "correlationDensity": round(correlation_density, 4), "eventsEvaluated": len(relevant), "formula": "0.20 chronology + 0.35 supported transitions + 0.30 entity continuity + 0.15 correlation density"}
    return round(score, 4), details


def build_graph(case_id: str, artifacts: list[dict[str, Any]], events: list[dict[str, Any]]) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    graph = nx.MultiDiGraph(case_id=case_id, engine=f"NetworkX {nx.__version__}")
    for artifact in artifacts:
        graph.add_node(f"artifact:{artifact['id']}", label=artifact["name"], kind="artifact", evidenceIds=[artifact["id"]], provenanceHash=artifact["sha256"])
    relevant = [event for event in events if event["classification"] != "NORMAL"]
    for event in relevant:
        event_node = f"event:{event['id']}"
        graph.add_node(event_node, label=event["eventType"].replace("_", " "), kind="event", evidenceIds=[event["artifactId"]], eventId=event["id"], provenanceHash=event["provenanceHash"])
        graph.add_edge(event_node, f"artifact:{event['artifactId']}", relation="OBSERVED_IN", evidenceIds=[event["id"]])
        for entity in event["entities"]:
            if entity["type"].startswith("semantic_") or entity["type"] in {"user", "host", "process", "ip", "domain", "file", "url", "hash"}:
                entity_node = f"entity:{entity['type']}:{entity['value'].lower()}"
                graph.add_node(entity_node, label=entity["value"], kind=entity["type"], evidenceIds=[event["artifactId"]])
                graph.add_edge(event_node, entity_node, relation="MENTIONS", evidenceIds=[event["id"]])
        for mapping in event["mitre"]:
            technique_node = f"technique:{mapping['techniqueId']}"
            graph.add_node(technique_node, label=mapping["techniqueId"], kind="technique", name=mapping["technique"], tactic=mapping["tactic"], evidenceIds=[event["artifactId"]])
            graph.add_edge(event_node, technique_node, relation="MAPS_TO", evidenceIds=[event["id"]])
    correlations = []
    ordered = sorted(relevant, key=lambda item: item["timestamp"])
    for index, left in enumerate(ordered):
        left_time = datetime.fromisoformat(left["timestamp"].replace("Z", "+00:00"))
        left_entities = {(item["type"], item["value"].lower()) for item in left["entities"]}
        for right in ordered[index + 1 :]:
            right_time = datetime.fromisoformat(right["timestamp"].replace("Z", "+00:00"))
            minutes = (right_time - left_time).total_seconds() / 60
            if minutes > 45:
                break
            right_entities = {(item["type"], item["value"].lower()) for item in right["entities"]}
            shared = sorted(f"{kind}:{value}" for kind, value in left_entities & right_entities)
            if shared:
                weight = round(min(1.0, 0.45 + 0.1 * len(shared) + 0.35 * (1 - minutes / 45)), 4)
                edge = {"source": f"event:{left['id']}", "target": f"event:{right['id']}", "relation": "CORRELATES_WITH", "weight": weight, "sharedEntities": shared, "minutesApart": round(minutes, 2), "evidenceIds": [left["id"], right["id"]]}
                graph.add_edge(edge["source"], edge["target"], **{key: value for key, value in edge.items() if key not in {"source", "target"}})
                correlations.append(edge)
    nodes = [{"id": node_id, **data} for node_id, data in graph.nodes(data=True)]
    edges = [{"id": f"edge-{index}", "source": source, "target": target, **data} for index, (source, target, data) in enumerate(graph.edges(data=True))]
    return {"engine": f"NetworkX {nx.__version__}", "directed": True, "multigraph": True, "nodes": nodes, "edges": edges}, correlations


def evidence_analysis(techniques: list[dict[str, Any]], observed_types: set[str]) -> tuple[list[dict[str, Any]], float, list[dict[str, Any]]]:
    by_type: dict[str, dict[str, Any]] = {}
    for technique in techniques:
        for evidence_type, relevance, reason in REQUIREMENTS.get(technique["techniqueId"], []):
            item = by_type.setdefault(evidence_type, {"type": evidence_type, "label": EVIDENCE_LABELS[evidence_type], "weight": 0.0, "techniques": set(), "reasons": set()})
            item["weight"] += relevance
            item["techniques"].add(technique["techniqueId"])
            item["reasons"].add(reason)
    requirements = []
    total = sum(item["weight"] for item in by_type.values())
    for item in by_type.values():
        requirements.append({"type": item["type"], "label": item["label"], "weight": round(item["weight"], 4), "normalizedWeight": round(item["weight"] / total, 4) if total else 0.0, "status": "PRESENT" if item["type"] in observed_types else "MISSING", "techniques": sorted(item["techniques"]), "reasons": sorted(item["reasons"])})
    coverage = sum(item["normalizedWeight"] for item in requirements if item["status"] == "PRESENT")
    max_weight = max((item["weight"] for item in requirements), default=1.0)
    max_techniques = max((len(item["techniques"]) for item in requirements), default=1)
    refute_value = {"email_headers": 1.0, "pcap": 1.0, "memory": 0.95, "sysmon": 0.85, "dns": 0.8, "proxy": 0.8, "registry": 0.85, "firewall": 0.7, "endpoint_auth": 0.75, "edr": 0.85, "browser_history": 0.7, "ids": 0.65}
    recommendations = []
    for item in requirements:
        if item["status"] == "PRESENT":
            continue
        relevance = item["weight"] / max_weight
        stage_support = len(item["techniques"]) / max_techniques
        confidence_contribution = item["normalizedWeight"]
        refute = refute_value.get(item["type"], 0.5)
        score = 100 * (0.45 * relevance + 0.25 * stage_support + 0.2 * confidence_contribution + 0.1 * refute)
        recommendations.append({**item, "recommendationScore": round(score, 1), "estimatedCoverageGain": round(item["normalizedWeight"] * 100, 1), "estimatedConfidenceGain": round(0.35 * item["normalizedWeight"] * 100, 1), "scoreFormula": {"techniqueRelevance": round(relevance, 4), "stageSupport": round(stage_support, 4), "confidenceContribution": round(confidence_contribution, 4), "confirmOrRefuteValue": round(refute, 4), "formula": "100 × (0.45 relevance + 0.25 stage support + 0.20 confidence contribution + 0.10 confirm/refute value)"}})
    recommendations.sort(key=lambda item: (-item["recommendationScore"], item["type"]))
    requirements.sort(key=lambda item: (-item["weight"], item["type"]))
    return requirements, round(min(1.0, coverage), 4), recommendations


def build_report(case_id: str, artifacts: list[dict[str, Any]], events: list[dict[str, Any]], hypothesis: dict[str, Any], techniques: list[dict[str, Any]], confidence: dict[str, Any], recommendations: list[dict[str, Any]]) -> dict[str, Any]:
    relevant = [event for event in events if event["classification"] != "NORMAL"]
    affected = sorted({entity["value"] for event in relevant for entity in event["entities"] if entity["type"] in {"user", "host", "process", "ip", "domain"}})
    return {
        "title": "Evidence-Grounded Forensic Report",
        "generationMethod": "Deterministic template over the current calculated investigation state; no LLM/RAG.",
        "caseSummary": f"Case {case_id} contains {len(artifacts)} evidence artifacts and {len(events)} normalized events. {len(relevant)} events were classified as suspicious or malicious.",
        "attackHypothesis": hypothesis["title"],
        "evidenceAnalyzed": [{"name": item["name"], "type": EVIDENCE_LABELS.get(item["type"], item["type"]), "sha256": item["sha256"]} for item in artifacts],
        "timeline": [{"timestamp": item["timestamp"], "event": item["eventType"], "classification": item["classification"], "probability": item["classificationProbability"], "source": item["sourceFile"], "mitre": [mapping["techniqueId"] for mapping in item["mitre"]]} for item in relevant],
        "mitre": techniques,
        "affectedEntities": affected[:20],
        "confidence": confidence,
        "missingEvidence": [{"type": item["label"], "score": item["recommendationScore"], "why": item["reasons"]} for item in recommendations[:5]],
        "explainabilitySummary": "Event probabilities are produced by XGBoost from DistilBERT embeddings plus structured features. Event-level SHAP values identify model contributions; evidence references provide provenance traceability.",
        "limitations": [f"{item['label']} is missing and may confirm or refute {', '.join(item['techniques'])}." for item in recommendations[:3]] or ["No matrix-defined evidence gaps remain for detected techniques."],
        "recommendedActions": [f"Collect and validate {item['label']} (recommendation score {item['recommendationScore']})." for item in recommendations[:3]],
    }


def analyse(case_id: str, raw_artifacts: list[dict[str, Any]], models: ModelBundle) -> dict[str, Any]:
    artifacts = []
    events = []
    dropped_rows = 0
    for artifact_index, raw in enumerate(raw_artifacts):
        artifact_id = str(raw.get("id") or f"artifact-{artifact_index + 1}")
        name = str(raw.get("name") or f"evidence-{artifact_index + 1}")
        text = str(raw.get("text") or "")
        actual_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
        supplied_hash = str(raw.get("sha256") or "")
        if not supplied_hash:
            raise ValueError(f"Evidence SHA-256 missing for {name}; analysis rejected.")
        if supplied_hash != actual_hash:
            raise ValueError(f"Evidence SHA-256 mismatch for {name}; analysis rejected.")
        evidence_type = detect_evidence_type(name, text, str(raw.get("type") or "unknown"))
        parse_error = ""
        try:
            rows = parse_rows(text, name)
        except (ValueError, json.JSONDecodeError, csv.Error) as error:
            rows = []
            parse_error = str(error)
        provenance_checks = {
            "hashGenerated": bool(actual_hash), "hashMatchesClient": bool(supplied_hash and supplied_hash == actual_hash),
            "parsedSuccessfully": bool(rows) and not parse_error, "sourceMetadataAvailable": bool(name and evidence_type),
            "associatedWithCase": bool(case_id),
        }
        provenance_score = round(sum(provenance_checks.values()) / len(provenance_checks), 4)
        artifacts.append({"id": artifact_id, "name": name, "type": evidence_type, "sha256": actual_hash, "clientSha256": supplied_hash, "size": len(text.encode("utf-8")), "ingestedAt": raw.get("ingestedAt") or datetime.now(timezone.utc).isoformat(), "parseError": parse_error, "rowCount": len(rows), "provenanceChecks": provenance_checks, "provenanceScore": provenance_score})
        for row_index, row in enumerate(rows):
            timestamp = valid_timestamp(row_value(row, "timestamp"))
            if not timestamp:
                dropped_rows += 1
                continue
            event_id = row_value(row, "event_id") or f"{artifact_id}-event-{row_index + 1}"
            event = {
                "id": event_id, "timestamp": timestamp, "source_type": evidence_type, "source_file": name,
                "artifact_id": artifact_id, "host": row_value(row, "host"), "user": row_value(row, "user"),
                "process": row_value(row, "process"), "parent_process": row_value(row, "parent_process"),
                "src_ip": row_value(row, "src_ip"), "dst_ip": row_value(row, "dst_ip"), "domain": row_value(row, "domain"),
                "url": row_value(row, "url"), "event_type": normalise_key(row_value(row, "event_type") or "observed_activity"),
                "status": row_value(row, "status") or "unknown", "resource": row_value(row, "resource"),
                "message": row_value(row, "message") or "No additional message", "raw_event": row,
                "provenance_hash": actual_hash,
            }
            event["normalized_text"] = event_text(event)
            events.append(event)
    events.sort(key=lambda item: item["timestamp"])
    if events:
        matrix, probabilities = models.predict(events)
        shap_values = models.explain(matrix, probabilities)
        ner_enabled = os.getenv("AICSI_ENABLE_NER", "1") == "1"
        semantic = models.semantic_entities([event["message"] for event in events]) if ner_enabled else [[] for _ in events]
        for index, event in enumerate(events):
            class_index = int(np.argmax(probabilities[index]))
            event["classification"] = models.classes[class_index]
            event["classificationProbability"] = round(float(probabilities[index, class_index]), 4)
            event["classProbabilities"] = {label: round(float(probabilities[index, label_index]), 4) for label_index, label in enumerate(models.classes)}
            event["shap"] = shap_values[index]
            event["entities"] = deterministic_entities(event) + semantic[index]
            event["mitre"] = map_mitre(event)
            event["artifactId"] = event.pop("artifact_id")
            event["sourceType"] = event.pop("source_type")
            event["sourceFile"] = event.pop("source_file")
            event["eventType"] = event.pop("event_type")
            event["parentProcess"] = event.pop("parent_process")
            event["srcIp"] = event.pop("src_ip")
            event["dstIp"] = event.pop("dst_ip")
            event["rawEvent"] = event.pop("raw_event")
            event["provenanceHash"] = event.pop("provenance_hash")
            event.pop("normalized_text", None)
    hypothesis = hypothesis_from_evidence(events)
    technique_map: dict[str, dict[str, Any]] = {}
    for event in events:
        if event["classification"] == "NORMAL":
            continue
        for mapping in event["mitre"]:
            item = technique_map.setdefault(mapping["techniqueId"], {**mapping, "evidenceEventIds": [], "sourceFiles": set()})
            item["evidenceEventIds"].append(event["id"])
            item["sourceFiles"].add(event["sourceFile"])
    techniques = [{**item, "sourceFiles": sorted(item["sourceFiles"])} for item in technique_map.values()]
    graph, correlation_edges = build_graph(case_id, artifacts, events)
    observed_types = {artifact["type"] for artifact in artifacts if artifact["provenanceChecks"]["parsedSuccessfully"]}
    requirements, evidence_coverage, recommendations = evidence_analysis(techniques, observed_types)
    relevant_probabilities = [event["classificationProbability"] for event in events if event["classification"] != "NORMAL"]
    model_confidence = float(np.mean(relevant_probabilities)) if relevant_probabilities else (float(np.mean([event["classificationProbability"] for event in events])) if events else 0.0)
    temporal, temporal_details = temporal_score(events, correlation_edges)
    provenance = float(np.mean([artifact["provenanceScore"] for artifact in artifacts])) if artifacts else 0.0
    overall = 100 * (0.35 * evidence_coverage + 0.25 * model_confidence + 0.25 * temporal + 0.15 * provenance)
    confidence = {
        "evidenceCoverage": round(evidence_coverage, 4), "modelConfidence": round(model_confidence, 4),
        "temporalCoherence": round(temporal, 4), "provenanceIntegrity": round(provenance, 4),
        "overall": round(overall, 1), "label": "High" if overall >= 80 else "Moderate" if overall >= 60 else "Low",
        "calculation": f"100 × [(0.35 × {evidence_coverage:.4f}) + (0.25 × {model_confidence:.4f}) + (0.25 × {temporal:.4f}) + (0.15 × {provenance:.4f})] = {overall:.1f}%",
        "modelDetails": {"model": "XGBoost XGBClassifier", "input": "768-dimensional DistilBERT embedding + 10 structured features", "eventsAggregated": len(relevant_probabilities), "aggregation": "Mean winning-class probability across non-normal events; all events if no non-normal prediction."},
        "temporalDetails": temporal_details,
        "provenanceDetails": {"artifactsPassedAllChecks": sum(all(item["provenanceChecks"].values()) for item in artifacts), "artifactCount": len(artifacts), "aggregation": "Mean of five implemented checks per artifact."},
    }
    report = build_report(case_id, artifacts, events, hypothesis, techniques, confidence, recommendations)
    return {
        "caseId": case_id, "analysedAt": datetime.now(timezone.utc).isoformat(), "artifacts": artifacts,
        "events": events, "droppedRows": dropped_rows, "hypothesis": hypothesis, "mitre": techniques,
        "graph": graph, "correlations": correlation_edges, "coverageRequirements": requirements,
        "recommendations": recommendations, "confidence": confidence, "report": report,
        "system": {
            "distilbert": {"status": "REAL", "model": EMBEDDING_MODEL, "license": "Apache-2.0", "purpose": "Contextual event embeddings", "dimension": models.embedding.dimension},
            "xgboost": {"status": "REAL", "modelPath": "models/event_classifier.json", "purpose": "Three-class event classification", "metrics": models.metadata.get("metrics", {})},
            "transformerNer": {"status": "REAL" if os.getenv("AICSI_ENABLE_NER", "1") == "1" else "DISABLED", "model": NER_MODEL, "purpose": "Semantic entities in unstructured messages only"},
            "iocExtraction": {"status": "DETERMINISTIC", "purpose": "Structured fields and regex validation for IOCs"},
            "networkx": {"status": "REAL", "version": nx.__version__, "purpose": "Dynamic investigation graph and correlation edges"},
            "mitreAttack": {"status": "OFFICIAL SUBSET", "version": ATTACK["version"], "source": ATTACK["source_url"], "license": ATTACK["license"]},
            "shap": {"status": "REAL", "purpose": "TreeExplainer event-level feature contributions"},
            "missingEvidenceEngine": {"status": "CUSTOM AI-CSI LOGIC"},
            "confidenceEngine": {"status": "CUSTOM AI-CSI LOGIC"},
            "forensicReport": {"status": "DETERMINISTIC EVIDENCE-GROUNDED"},
            "llmRag": {"status": "REVIEW 3 REPORT AND Q&A AVAILABLE", "purpose": "Server-side LLM claim selection with cited deterministic rendering"},
        },
    }
