"""Review 3 reporting over a server-held, verified investigation snapshot.

The language model may select claim IDs, but it never authors forensic facts. Every
rendered sentence comes from the structured analysis and carries source references.
"""
from __future__ import annotations

import io
import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any

import httpx
from dotenv import dotenv_values


def _ref(event: dict[str, Any]) -> dict[str, str]:
    return {"artifactId": event["artifactId"], "eventId": event["id"],
            "sourceFile": event["sourceFile"], "sha256": event["provenanceHash"]}


def _event_label(event: dict[str, Any]) -> str:
    return event["eventType"].replace("_", " ").lower()


def _event_time(event: dict[str, Any]) -> str:
    date = datetime.strptime(event["timestamp"][:10], "%Y-%m-%d").strftime("%d %b %Y")
    return f"{event['timestamp'][11:16]} UTC on {date}"


def _friendly_event(event: dict[str, Any], first: bool = False) -> str:
    opening = "The records begin" if first else "The next record appears"
    sentence = f"{opening} at {_event_time(event)} with {_event_label(event)}"
    if event.get("user"):
        sentence += f" for {event['user']}"
    if event.get("host"):
        sentence += f" on {event['host']}"
    if event.get("srcIp"):
        sentence += f" from {event['srcIp']}"
    if event.get("dstIp"):
        sentence += f" to {event['dstIp']}"
    if event.get("process"):
        sentence += f" using {event['process']}"
    if event.get("resource"):
        sentence += f", involving {event['resource']}"
    return sentence + "."


def claims_for(analysis: dict[str, Any]) -> list[dict[str, Any]]:
    claims: list[dict[str, Any]] = []
    for index, artifact in enumerate(analysis["artifacts"], 1):
        claims.append({"id": f"A{index}", "kind": "observed", "section": "inventory",
                       "text": f"{artifact['name']} was ingested as {artifact['type']} with {artifact['rowCount']} parsed rows. Its SHA-256 was independently verified: {artifact['sha256']}.",
                       "friendly": f"We reviewed {artifact['name']} and verified its SHA-256 hash. It contains {artifact['rowCount']} parsed records.",
                       "citations": [{"artifactId": artifact["id"], "sourceFile": artifact["name"], "sha256": artifact["sha256"]}]})
    for index, event in enumerate(analysis["events"], 1):
        facts = [event["eventType"].replace("_", " ")]
        for key, label in (("user", "user"), ("host", "host"), ("srcIp", "source IP"), ("dstIp", "destination IP"), ("process", "process"), ("resource", "resource")):
            if event.get(key):
                facts.append(f"{label} {event[key]}")
        ref = _ref(event)
        claims.append({"id": f"E{index}", "kind": "observed", "section": "timeline", "timestamp": event["timestamp"],
                       "text": f"At {event['timestamp']}, {', '.join(facts)} was recorded in {event['sourceFile']}.",
                       "friendly": _friendly_event(event, first=index == 1), "citations": [ref]})
        if event["classification"] != "NORMAL":
            claims.append({"id": f"D{index}", "kind": "model inference", "section": "detections", "timestamp": event["timestamp"],
                           "text": f"The existing XGBoost model classified event {event['id']} as {event['classification']} with winning-class probability {event['classificationProbability']:.1%}.",
                           "friendly": f"The model gave the {_event_label(event)} at {_event_time(event)} a {event['classification'].lower()} label, with a score of {event['classificationProbability']:.1%}. This is a lead to investigate, not a confirmed finding.",
                           "citations": [ref]})
        for mapping in event["mitre"]:
            claims.append({"id": f"T{index}-{mapping['techniqueId']}", "kind": "rule mapping", "section": "mitre", "timestamp": event["timestamp"],
                           "text": f"Event {event['id']} maps by the existing rule set to MITRE ATT&CK {mapping['techniqueId']} ({mapping['technique']}; {mapping['tactic']}).",
                           "friendly": f"The rule-based mapping links the {_event_label(event)} at {_event_time(event)} to MITRE ATT&CK {mapping['techniqueId']} ({mapping['technique']}, {mapping['tactic']}).",
                           "citations": [ref]})
        if event.get("shap") and event["classification"] != "NORMAL":
            top = sorted(event["shap"], key=lambda item: abs(item["value"]), reverse=True)[:3]
            detail = ", ".join(f"{item['feature']} ({item['value']:+.3f})" for item in top)
            claims.append({"id": f"S{index}", "kind": "model explanation", "section": "shap",
                           "text": f"For event {event['id']}, the largest absolute TreeSHAP feature contributions were {detail}. These explain the model score, not causation.",
                           "friendly": f"For the {_event_label(event)} at {_event_time(event)}, SHAP points most strongly to {detail}. These values explain the model's score; they do not prove a cause.",
                           "citations": [ref]})
    for index, item in enumerate(analysis["recommendations"], 1):
        supporting = [claim["citations"][0] for claim in claims if claim["section"] == "mitre" and any(t in claim["id"] for t in item["techniques"])]
        if not supporting:
            supporting = [claim["citations"][0] for claim in claims if claim["section"] == "inventory"]
        claims.append({"id": f"M{index}", "kind": "evidence gap", "section": "missing",
                       "text": f"{item['label']} is missing for mapped techniques {', '.join(item['techniques'])}. Collection may confirm or refute the current interpretation. Recommendation score: {item['recommendationScore']:.1f}.",
                       "friendly": f"To check the current interpretation, collect {item['label'].lower()}. That evidence may confirm or challenge the mapping to {', '.join(item['techniques'])}.",
                       "citations": supporting[:3]})
    return claims


def _llm_select(prompt: str, allowed: list[str], limit: int) -> tuple[list[str], str]:
    provider = os.getenv("AICSI_LLM_PROVIDER", "ollama").lower()
    if provider == "disabled":
        return [], "disabled"
    model = os.getenv("AICSI_LLM_MODEL", "gpt-6-luna" if provider == "openai" else "qwen2.5:3b")
    system = "You organize an investigation using only supplied claim IDs. Return JSON {\"ids\":[...]} with relevant IDs only. Never write facts, prose, or new IDs."
    try:
        if provider == "ollama":
            base = os.getenv("AICSI_OLLAMA_URL", "http://127.0.0.1:11434").rstrip("/")
            response = httpx.post(f"{base}/api/chat", json={"model": model, "stream": False, "format": "json", "options": {"temperature": 0},
                "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}]}, timeout=35)
            response.raise_for_status()
            content = response.json()["message"]["content"]
        elif provider == "openai":
            key = os.getenv("OPENAI_API_KEY") or dotenv_values(Path(__file__).with_name(".env")).get("OPENAI_API_KEY") or ""
            if not key:
                return [], "OpenAI key missing"
            response = httpx.post("https://api.openai.com/v1/responses",
                headers={"Authorization": f"Bearer {key}"},
                json={"model": model, "store": False, "input": [
                    {"role": "system", "content": system}, {"role": "user", "content": prompt}],
                    "text": {"format": {"type": "json_schema", "name": "claim_selection", "strict": True,
                        "schema": {"type": "object", "properties": {"ids": {"type": "array", "items": {"type": "string", "enum": allowed}}},
                                   "required": ["ids"], "additionalProperties": False}}}}, timeout=35)
            response.raise_for_status()
            content = next(part["text"] for item in response.json().get("output", []) if item.get("type") == "message"
                           for part in item.get("content", []) if part.get("type") == "output_text")
        elif provider == "openai_compatible":
            base = os.getenv("AICSI_LLM_BASE_URL", "").rstrip("/")
            key = os.getenv("AICSI_LLM_API_KEY", "")
            if not base or not key:
                return [], "configuration missing"
            response = httpx.post(f"{base}/chat/completions", headers={"Authorization": f"Bearer {key}"},
                json={"model": model, "temperature": 0, "response_format": {"type": "json_object"},
                      "messages": [{"role": "system", "content": system}, {"role": "user", "content": prompt}]}, timeout=35)
            response.raise_for_status()
            content = response.json()["choices"][0]["message"]["content"]
        else:
            return [], "unsupported provider"
        selected = json.loads(content).get("ids", [])
        if not isinstance(selected, list):
            return [], "invalid LLM response"
        valid = list(dict.fromkeys(value for value in selected if isinstance(value, str) and value in allowed))[:limit]
        return valid, "ready" if valid else "no supported selection"
    except (httpx.HTTPError, KeyError, ValueError, TypeError, StopIteration, json.JSONDecodeError):
        return [], "unavailable or invalid response"


def _format(claim: dict[str, Any]) -> dict[str, Any]:
    return {"id": claim["id"], "kind": claim["kind"], "text": claim.get("friendly", claim["text"]), "citations": claim["citations"]}


def build_review3(analysis: dict[str, Any]) -> dict[str, Any]:
    claims = claims_for(analysis)
    summary_pool = [claim for claim in claims if claim["section"] in {"detections", "mitre", "missing"}][:60]
    prompt = f"Select up to 6 most important claim IDs for an executive summary of case {analysis['caseId']}. Claims: " + json.dumps([{"id": c["id"], "text": c["text"]} for c in summary_pool])
    selected, status = _llm_select(prompt, [c["id"] for c in summary_pool], 6)
    if not selected:
        selected = [c["id"] for c in summary_pool[:6]]
    by_id = {c["id"]: c for c in claims}
    timeline = [c for c in claims if c["section"] == "timeline"]
    detections = [c for c in claims if c["section"] == "detections"]
    limitations = ["Model detections and ATT&CK mappings are investigative leads; they do not prove who caused the activity.",
                   "Missing evidence could change this interpretation, so the reconstruction is not yet complete."]
    if analysis["droppedRows"]:
        limitations.append(f"The timeline excludes {analysis['droppedRows']} records without a usable timestamp.")
    return {"caseId": analysis["caseId"], "analysedAt": analysis["analysedAt"], "llmStatus": status,
            "generationMethod": "AI selected evidence-backed findings for this report" if status == "ready" else "Evidence-backed report; AI assistance " + status,
            "summary": [_format(by_id[c]) for c in selected],
            "story": [_format(c) for c in timeline], "detections": [_format(c) for c in detections],
            "mitre": [_format(c) for c in claims if c["section"] == "mitre"],
            "shap": [_format(c) for c in claims if c["section"] == "shap"],
            "missingEvidence": [_format(c) for c in claims if c["section"] == "missing"],
            "inventory": [_format(c) for c in claims if c["section"] == "inventory"],
            "confidence": analysis["confidence"], "droppedRows": analysis["droppedRows"],
            "limitations": limitations,
            "conclusion": "Taken together, these records give investigators a useful starting picture. Check the cited files and collect the missing sources before drawing a final conclusion."}


def answer_question(analysis: dict[str, Any], question: str) -> dict[str, Any]:
    claims = claims_for(analysis)
    terms = set(re.findall(r"[a-z0-9.]+", question.lower())) - {"what", "when", "where", "which", "were", "about", "this", "that", "does", "show", "case", "have", "did", "the", "and", "for", "from", "with", "are", "was", "happened", "after", "before"}
    candidates = [c for c in claims if terms and any(term in c["text"].lower() or term in c["id"].lower() for term in terms)]
    direction = "after" if re.search(r"\bafter\b", question, re.I) else "before" if re.search(r"\bbefore\b", question, re.I) else ""
    if direction and analysis["events"]:
        ranked = sorted(enumerate(analysis["events"]), key=lambda pair: (-sum(term in _event_label(pair[1]) for term in terms), pair[0]))
        if ranked and any(term in _event_label(ranked[0][1]) for term in terms):
            anchor_time = ranked[0][1]["timestamp"]
            candidates = [c for c in claims if c["section"] == "timeline" and
                          (c["timestamp"] > anchor_time if direction == "after" else c["timestamp"] < anchor_time)]
        else:
            direction = ""
    if not candidates:
        return {"answer": "I cannot answer that from the evidence in this case yet. Try adding a relevant source and running the analysis again.", "claims": [], "llmStatus": "insufficient evidence"}
    pool = candidates[:5] if direction == "after" else candidates[-5:] if direction == "before" else candidates[:60]
    prompt = f"Question: {question}\nSelect up to 5 directly relevant claim IDs. Claims: " + json.dumps([{"id": c["id"], "text": c["text"]} for c in pool])
    selected, status = _llm_select(prompt, [c["id"] for c in pool], 5)
    if not selected:
        selected = [c["id"] for c in pool[:3]]
    if direction:
        nearest = pool[:2] if direction == "after" else pool[-2:]
        selected = list(dict.fromkeys([c["id"] for c in nearest] + selected))[:5]
    by_id = {c["id"]: c for c in pool}
    rendered = [_format(by_id[c]) for c in selected]
    if direction:
        order = {claim["id"]: index for index, claim in enumerate(pool)}
        rendered.sort(key=lambda claim: order[claim["id"]])
    introduction = f"{direction.capitalize()} that event, the available records show: " if direction else "Here is what the available evidence shows. "
    return {"answer": introduction + " ".join(f"{c['text']} [{c['id']}]" for c in rendered), "claims": rendered, "llmStatus": status}


def render_pdf(report: dict[str, Any]) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import A4
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, KeepTogether
    from xml.sax.saxutils import escape

    buffer = io.BytesIO()
    navy, teal = colors.HexColor("#123047"), colors.HexColor("#087f74")
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="CoverTitle", parent=styles["Title"], fontSize=24, leading=29, textColor=navy, spaceAfter=15))
    styles.add(ParagraphStyle(name="SectionCustom", parent=styles["Heading2"], fontSize=13, leading=17, textColor=teal, spaceBefore=16, spaceAfter=7))
    styles.add(ParagraphStyle(name="BodyCustom", parent=styles["BodyText"], fontSize=9, leading=13, spaceAfter=6))
    styles.add(ParagraphStyle(name="SmallCustom", parent=styles["BodyText"], fontSize=7, leading=10, textColor=colors.HexColor("#536777"), spaceAfter=9))
    doc = SimpleDocTemplate(buffer, pagesize=A4, leftMargin=43, rightMargin=43, topMargin=50, bottomMargin=48)
    flow = [Paragraph("AI-CSI Forensic Investigation Report", styles["CoverTitle"]),
            Paragraph(f"Case {escape(report['caseId'])} | Analysis {escape(report['analysedAt'])}", styles["BodyCustom"]),
            Paragraph(escape(report["generationMethod"]), styles["SmallCustom"]), Spacer(1, 8)]
    sections = [("The short version", "summary"), ("Evidence reviewed and verified", "inventory"),
                ("How the events unfolded", "story"), ("What the model flagged", "detections"),
                ("How activity maps to MITRE ATT&CK", "mitre"), ("What influenced the model", "shap"),
                ("Evidence that would help next", "missingEvidence")]
    for title, key in sections:
        flow.append(Paragraph(title, styles["SectionCustom"]))
        if not report[key]:
            flow.append(Paragraph("The current evidence does not support a finding here.", styles["BodyCustom"]))
        for claim in report[key]:
            citations = "; ".join(f"{r['sourceFile']} / {r.get('eventId', r['artifactId'])} / SHA-256 {r['sha256'][:16]}..." for r in claim["citations"])
            flow.append(KeepTogether([Paragraph(escape(claim['text']) + f" <font color='#087f74'>[{escape(claim['id'])}]</font>", styles["BodyCustom"]),
                                      Paragraph("Evidence: " + escape(citations), styles["SmallCustom"])]))
    flow.append(Paragraph("Confidence and what remains uncertain", styles["SectionCustom"]))
    flow.append(Paragraph(f"Current evidential support is {report['confidence']['overall']:.1f}% ({escape(report['confidence']['label'].lower())}). This score describes support in the available evidence, not certainty about the incident.", styles["BodyCustom"]))
    flow.append(Paragraph(escape(report["confidence"]["calculation"]), styles["SmallCustom"]))
    for limitation in report["limitations"]:
        flow.append(Paragraph(escape(limitation), styles["BodyCustom"]))
    flow.append(Paragraph("Overall assessment", styles["SectionCustom"]))
    flow.append(Paragraph(escape(report["conclusion"]), styles["BodyCustom"]))
    flow.append(Paragraph("Appendix: full source hashes and citation key", styles["SectionCustom"]))
    for claim in report["inventory"]:
        for ref in claim["citations"]:
            flow.append(Paragraph(escape(f"[{claim['id']}] {ref['sourceFile']} | {ref['artifactId']} | SHA-256 {ref['sha256']}"), styles["SmallCustom"]))
    def footer(canvas, document):
        canvas.setStrokeColor(colors.HexColor("#d7e3e7")); canvas.line(43, 39, A4[0]-43, 39)
        canvas.setFont("Helvetica", 7); canvas.setFillColor(navy)
        canvas.drawString(43, 28, f"AI-CSI | {report['caseId']} | Evidence-grounded investigation")
        canvas.drawRightString(A4[0]-43, 28, f"Page {document.page}")
    doc.build(flow, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()
