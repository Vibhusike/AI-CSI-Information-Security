"""Review 3 reporting over a server-held, verified investigation snapshot.

The language model may select claim IDs, but it never authors forensic facts. Every
rendered sentence comes from the structured analysis and carries source references.
"""
from __future__ import annotations

import io
import json
import os
import re
from pathlib import Path
from typing import Any

import httpx
from dotenv import dotenv_values


def _ref(event: dict[str, Any]) -> dict[str, str]:
    return {"artifactId": event["artifactId"], "eventId": event["id"],
            "sourceFile": event["sourceFile"], "sha256": event["provenanceHash"]}


def claims_for(analysis: dict[str, Any]) -> list[dict[str, Any]]:
    claims: list[dict[str, Any]] = []
    for index, artifact in enumerate(analysis["artifacts"], 1):
        claims.append({"id": f"A{index}", "kind": "observed", "section": "inventory",
                       "text": f"{artifact['name']} was ingested as {artifact['type']} with {artifact['rowCount']} parsed rows. Its SHA-256 was independently verified: {artifact['sha256']}.",
                       "citations": [{"artifactId": artifact["id"], "sourceFile": artifact["name"], "sha256": artifact["sha256"]}]})
    for index, event in enumerate(analysis["events"], 1):
        facts = [event["eventType"].replace("_", " ")]
        for key, label in (("user", "user"), ("host", "host"), ("srcIp", "source IP"), ("dstIp", "destination IP"), ("process", "process"), ("resource", "resource")):
            if event.get(key):
                facts.append(f"{label} {event[key]}")
        ref = _ref(event)
        claims.append({"id": f"E{index}", "kind": "observed", "section": "timeline", "timestamp": event["timestamp"],
                       "text": f"At {event['timestamp']}, {', '.join(facts)} was recorded in {event['sourceFile']}.", "citations": [ref]})
        if event["classification"] != "NORMAL":
            claims.append({"id": f"D{index}", "kind": "model inference", "section": "detections", "timestamp": event["timestamp"],
                           "text": f"The existing XGBoost model classified event {event['id']} as {event['classification']} with winning-class probability {event['classificationProbability']:.1%}.", "citations": [ref]})
        for mapping in event["mitre"]:
            claims.append({"id": f"T{index}-{mapping['techniqueId']}", "kind": "rule mapping", "section": "mitre", "timestamp": event["timestamp"],
                           "text": f"Event {event['id']} maps by the existing rule set to MITRE ATT&CK {mapping['techniqueId']} ({mapping['technique']}; {mapping['tactic']}).", "citations": [ref]})
        if event.get("shap") and event["classification"] != "NORMAL":
            top = sorted(event["shap"], key=lambda item: abs(item["value"]), reverse=True)[:3]
            detail = ", ".join(f"{item['feature']} ({item['value']:+.3f})" for item in top)
            claims.append({"id": f"S{index}", "kind": "model explanation", "section": "shap",
                           "text": f"For event {event['id']}, the largest absolute TreeSHAP feature contributions were {detail}. These explain the model score, not causation.", "citations": [ref]})
    for index, item in enumerate(analysis["recommendations"], 1):
        supporting = [claim["citations"][0] for claim in claims if claim["section"] == "mitre" and any(t in claim["id"] for t in item["techniques"])]
        if not supporting:
            supporting = [claim["citations"][0] for claim in claims if claim["section"] == "inventory"]
        claims.append({"id": f"M{index}", "kind": "evidence gap", "section": "missing",
                       "text": f"{item['label']} is missing for mapped techniques {', '.join(item['techniques'])}. Collection may confirm or refute the current interpretation. Recommendation score: {item['recommendationScore']:.1f}.",
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
    return {"id": claim["id"], "kind": claim["kind"], "text": claim["text"], "citations": claim["citations"]}


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
    return {"caseId": analysis["caseId"], "analysedAt": analysis["analysedAt"], "llmStatus": status,
            "generationMethod": "LLM claim selection with deterministic evidence-grounded rendering" if status == "ready" else "Deterministic evidence-grounded fallback; LLM " + status,
            "summary": [_format(by_id[c]) for c in selected],
            "story": [_format(c) for c in timeline], "detections": [_format(c) for c in detections],
            "mitre": [_format(c) for c in claims if c["section"] == "mitre"],
            "shap": [_format(c) for c in claims if c["section"] == "shap"],
            "missingEvidence": [_format(c) for c in claims if c["section"] == "missing"],
            "inventory": [_format(c) for c in claims if c["section"] == "inventory"],
            "confidence": analysis["confidence"], "droppedRows": analysis["droppedRows"],
            "limitations": ["Event labels, ATT&CK mappings, and SHAP values are model or rule interpretations, not direct observations.",
                            f"{analysis['droppedRows']} rows lacked usable timestamps and were excluded from the event timeline.",
                            "Missing evidence can change the current interpretation; no claim of complete reconstruction is made."],
            "conclusion": "The cited observations support the listed detections and mappings as investigative leads. Review the source artifacts and collect missing evidence before making a final attribution."}


def answer_question(analysis: dict[str, Any], question: str) -> dict[str, Any]:
    claims = claims_for(analysis)
    terms = set(re.findall(r"[a-z0-9.]+", question.lower())) - {"what", "when", "where", "which", "were", "about", "this", "that", "does", "show", "case", "have", "did", "the", "and", "for", "from", "with", "are", "was"}
    candidates = [c for c in claims if terms and any(term in c["text"].lower() or term in c["id"].lower() for term in terms)]
    if not candidates:
        return {"answer": "The current evidence does not support an answer to that question.", "claims": [], "llmStatus": "insufficient evidence"}
    pool = candidates[:60]
    prompt = f"Question: {question}\nSelect up to 5 directly relevant claim IDs. Claims: " + json.dumps([{"id": c["id"], "text": c["text"]} for c in pool])
    selected, status = _llm_select(prompt, [c["id"] for c in pool], 5)
    if not selected:
        selected = [c["id"] for c in pool[:3]]
    by_id = {c["id"]: c for c in pool}
    rendered = [_format(by_id[c]) for c in selected]
    return {"answer": " ".join(f"{c['text']} [{c['id']}]" for c in rendered), "claims": rendered, "llmStatus": status}


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
    sections = [("Executive summary", "summary"), ("Verified SHA-256 evidence inventory", "inventory"),
                ("Chronological attack story - observed events", "story"), ("Model detections - inferences", "detections"),
                ("MITRE ATT&CK rule mappings", "mitre"), ("TreeSHAP model explanations", "shap"),
                ("Missing evidence and recommendations", "missingEvidence")]
    for title, key in sections:
        flow.append(Paragraph(title, styles["SectionCustom"]))
        if not report[key]:
            flow.append(Paragraph("No supported entries in this section.", styles["BodyCustom"]))
        for claim in report[key]:
            citations = "; ".join(f"{r['sourceFile']} / {r.get('eventId', r['artifactId'])} / SHA-256 {r['sha256'][:16]}..." for r in claim["citations"])
            flow.append(KeepTogether([Paragraph(f"<b>[{escape(claim['id'])}] {escape(claim['kind'])}:</b> {escape(claim['text'])}", styles["BodyCustom"]),
                                      Paragraph("Sources: " + escape(citations), styles["SmallCustom"])]))
    flow.append(Paragraph("Confidence and limitations", styles["SectionCustom"]))
    flow.append(Paragraph(escape(report["confidence"]["calculation"]), styles["BodyCustom"]))
    for limitation in report["limitations"]:
        flow.append(Paragraph("- " + escape(limitation), styles["BodyCustom"]))
    flow.append(Paragraph("Conclusion", styles["SectionCustom"]))
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
