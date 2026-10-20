from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import numpy as np
import shap
import torch
import xgboost as xgb
from transformers import AutoModel, AutoModelForTokenClassification, AutoTokenizer, pipeline


ROOT = Path(__file__).resolve().parent.parent
MODEL_DIR = ROOT / "models"
EMBEDDING_MODEL = "distilbert/distilbert-base-uncased"
NER_MODEL = "elastic/distilbert-base-uncased-finetuned-conll03-english"
STRUCTURED_FEATURES = [
    "risk_keyword_count",
    "authentication_signal",
    "privilege_signal",
    "outbound_transfer_signal",
    "script_execution_signal",
    "malware_signal",
    "failure_status",
    "has_ip",
    "has_domain",
    "source_risk",
]


class EmbeddingEngine:
    def __init__(self, device: str = "cpu", max_length: int = 128) -> None:
        self.tokenizer = AutoTokenizer.from_pretrained(EMBEDDING_MODEL)
        self.model = AutoModel.from_pretrained(EMBEDDING_MODEL)
        self.device = torch.device(device)
        self.max_length = max_length
        self.model.to(self.device)
        self.model.eval()
        self.cache: dict[str, np.ndarray] = {}

    @property
    def dimension(self) -> int:
        return int(self.model.config.hidden_size)

    def encode(self, texts: list[str], batch_size: int = 128) -> np.ndarray:
        outputs: list[np.ndarray] = []
        missing: list[str] = []
        for text in texts:
            key = hashlib.sha256(text.encode("utf-8")).hexdigest()
            if key not in self.cache:
                missing.append(text)
        for start in range(0, len(missing), batch_size):
            batch = missing[start : start + batch_size]
            encoded = self.tokenizer(batch, padding=True, truncation=True, max_length=self.max_length, return_tensors="pt")
            encoded = {key: value.to(self.device) for key, value in encoded.items()}
            with torch.no_grad():
                hidden = self.model(**encoded).last_hidden_state
                mask = encoded["attention_mask"].unsqueeze(-1)
                pooled = (hidden * mask).sum(dim=1) / mask.sum(dim=1).clamp(min=1)
            for text, vector in zip(batch, pooled.cpu().numpy(), strict=True):
                self.cache[hashlib.sha256(text.encode("utf-8")).hexdigest()] = vector.astype(np.float32)
        for text in texts:
            outputs.append(self.cache[hashlib.sha256(text.encode("utf-8")).hexdigest()])
        return np.vstack(outputs) if outputs else np.empty((0, self.dimension), dtype=np.float32)


def structured_features(event: dict[str, Any]) -> np.ndarray:
    text = " ".join(str(event.get(key, "")) for key in ("event_type", "message", "status", "source_type")).lower()
    risk_words = (
        "phish", "malware", "ransomware", "encoded", "suspicious", "attacker", "exfil",
        "credential", "beacon", "tunnel", "injection", "impossible", "failed", "unsigned",
    )
    source_risk = {"ids": 0.9, "edr": 0.85, "memory": 0.8, "pcap": 0.75, "sysmon": 0.7,
                   "firewall": 0.55, "proxy": 0.55, "email_headers": 0.5, "dns": 0.45}.get(
        str(event.get("source_type", "unknown")), 0.25
    )
    return np.array([
        min(1.0, sum(word in text for word in risk_words) / 3),
        float(any(word in text for word in ("login", "auth", "mfa", "credential", "token"))),
        float(any(word in text for word in ("privilege", "admin", "elevat"))),
        float(any(word in text for word in ("upload", "exfil", "outbound", "transfer", "tunnel"))),
        float(any(word in text for word in ("powershell", "command", "script", "execute"))),
        float(any(word in text for word in ("malware", "ransomware", "injection", "payload"))),
        float(any(word in text for word in ("fail", "blocked", "alert", "detected", "confirmed"))),
        float(bool(event.get("src_ip") or event.get("dst_ip"))),
        float(bool(event.get("domain") or event.get("url"))),
        source_risk,
    ], dtype=np.float32)


class ModelBundle:
    def __init__(self) -> None:
        self.embedding = EmbeddingEngine()
        metadata_path = MODEL_DIR / "metadata.json"
        model_path = MODEL_DIR / "event_classifier.json"
        if not metadata_path.exists() or not model_path.exists():
            raise RuntimeError("Trained model artifacts are missing. Run: .venv/bin/python backend/train_model.py")
        self.metadata = json.loads(metadata_path.read_text())
        self.classes: list[str] = self.metadata["classes"]
        self.model = xgb.XGBClassifier()
        self.model.load_model(model_path)
        self.explainer = shap.TreeExplainer(self.model)
        self._ner: Any | None = None

    def feature_matrix(self, events: list[dict[str, Any]]) -> np.ndarray:
        texts = [event["normalized_text"] for event in events]
        embeddings = self.embedding.encode(texts)
        structured = np.vstack([structured_features(event) for event in events])
        return np.hstack([embeddings, structured]).astype(np.float32)

    def predict(self, events: list[dict[str, Any]]) -> tuple[np.ndarray, np.ndarray]:
        matrix = self.feature_matrix(events)
        probabilities = self.model.predict_proba(matrix)
        return matrix, probabilities

    def explain(self, matrix: np.ndarray, probabilities: np.ndarray) -> list[list[dict[str, float | str]]]:
        raw = np.asarray(self.explainer.shap_values(matrix))
        explanations: list[list[dict[str, float | str]]] = []
        for row_index in range(matrix.shape[0]):
            class_index = int(np.argmax(probabilities[row_index]))
            if raw.ndim == 3 and raw.shape[1] == matrix.shape[1]:
                values = raw[row_index, :, class_index]
            elif raw.ndim == 3:
                values = raw[class_index, row_index, :]
            elif raw.ndim == 2:
                values = raw[row_index]
            else:
                values = np.zeros(matrix.shape[1])
            embedding_total = float(values[: self.embedding.dimension].sum())
            items = [{"feature": "DistilBERT contextual embedding", "value": embedding_total}]
            for offset, name in enumerate(STRUCTURED_FEATURES):
                feature_index = self.embedding.dimension + offset
                items.append({"feature": name.replace("_", " "), "value": float(values[feature_index])})
            explanations.append(sorted(items, key=lambda item: abs(float(item["value"])), reverse=True)[:5])
        return explanations

    def semantic_entities(self, texts: list[str]) -> list[list[dict[str, str | float]]]:
        if self._ner is None:
            tokenizer = AutoTokenizer.from_pretrained(NER_MODEL)
            model = AutoModelForTokenClassification.from_pretrained(NER_MODEL)
            self._ner = pipeline("token-classification", model=model, tokenizer=tokenizer, aggregation_strategy="simple")
        results: list[list[dict[str, str | float]]] = []
        batches = self._ner([text[:512] for text in texts], batch_size=min(32, max(1, len(texts)))) if texts else []
        for raw_entities in batches:
            entities: list[dict[str, str | float]] = []
            for item in raw_entities:
                entities.append({
                    "type": f"semantic_{str(item['entity_group']).lower()}",
                    "value": str(item["word"]),
                    "confidence": round(float(item["score"]), 4),
                    "extractor": NER_MODEL,
                })
            results.append(entities)
        return results
