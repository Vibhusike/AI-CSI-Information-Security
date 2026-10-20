"""Reproducible Review 2 evaluation of the existing AI-CSI prototype.

The fixed candidate split is selected using labels and event-type groups only,
before any model is fitted. Test predictions do not affect model selection.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import statistics
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
import sklearn
import torch
import transformers
import xgboost
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import GroupShuffleSplit

from ml import EmbeddingEngine, structured_features

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "backend/data/training_events.csv"
SAMPLES = ROOT / "public/sample-data/review2"
CLASSES = ["MALICIOUS", "NORMAL", "SUSPICIOUS"]


def split_indices(frame: pd.DataFrame) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Choose a class-balanced, group-exclusive 60/20/20-ish split without using features."""
    labels = frame.label.to_numpy()
    groups = frame.event_type.to_numpy()
    candidates = GroupShuffleSplit(n_splits=120, test_size=0.20, random_state=42)
    best = None
    for trainval, test in candidates.split(frame, labels, groups):
        if set(labels[test]) != set(CLASSES):
            continue
        inner = GroupShuffleSplit(n_splits=30, test_size=0.25, random_state=43)
        for train_rel, val_rel in inner.split(frame.iloc[trainval], labels[trainval], groups[trainval]):
            train, val = trainval[train_rel], trainval[val_rel]
            if any(set(labels[idx]) != set(CLASSES) for idx in (train, val)):
                continue
            # Target 36/12/12 and 12/4/4 examples per class; selection uses labels only.
            targets = [(train, 36, 12), (val, 12, 4), (test, 12, 4)]
            score = sum(abs(len(idx) - n) + sum(abs(int(sum(labels[idx] == c)) - k) for c in CLASSES)
                        for idx, n, k in targets)
            if best is None or score < best[0]:
                best = (score, train, val, test)
    if best is None:
        raise RuntimeError("No valid three-class group split exists")
    _, train, val, test = best
    assert not (set(groups[train]) & set(groups[val]) or set(groups[train]) & set(groups[test]) or set(groups[val]) & set(groups[test]))
    assert len(set(frame.text.iloc[train]) & set(frame.text.iloc[test])) == 0
    return train, val, test


def metrics(y_true: np.ndarray, y_pred: np.ndarray) -> dict:
    report = classification_report(y_true, y_pred, labels=CLASSES, output_dict=True, zero_division=0)
    return {
        "n": int(len(y_true)),
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "macro_precision": float(report["macro avg"]["precision"]),
        "macro_recall": float(report["macro avg"]["recall"]),
        "macro_f1": float(report["macro avg"]["f1-score"]),
        "per_class": {c: report[c] for c in CLASSES},
        "confusion_matrix": confusion_matrix(y_true, y_pred, labels=CLASSES).tolist(),
    }


def artifact(name: str, declared_type: str) -> dict:
    raw = (SAMPLES / name).read_bytes()
    return {"id": name, "name": name, "type": declared_type, "text": raw.decode(),
            "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw), "ingestedAt": "2026-09-23T00:00:00Z"}


def security_experiments() -> dict:
    os.environ["AICSI_ENABLE_NER"] = "0"  # explicit speed setting; not a model comparison
    from ml import ModelBundle
    from pipeline import analyse
    from server import AnalysisRequest
    from pydantic import ValidationError

    model = ModelBundle()
    initial = [artifact("phishing_endpoint_auth.csv", "endpoint_auth"),
               artifact("phishing_firewall.csv", "firewall"), artifact("phishing_ids.jsonl", "ids")]
    t0 = time.perf_counter()
    original = analyse("ACSI-2026-EVAL", initial, model)
    first_seconds = time.perf_counter() - t0
    changed = [dict(x) for x in initial]
    changed[0]["text"] += "\n2026-09-12T11:00:00Z,forged_event,success,attacker inserted row\n"
    tamper_rejected = False
    tamper_error = ""
    try:
        analyse("ACSI-2026-EVAL", changed, model)
    except ValueError as error:
        tamper_rejected = True
        tamper_error = str(error)
    missing_hash_rejected = False
    try:
        analyse("ACSI-2026-EVAL", [dict(initial[0], sha256="")], model)
    except ValueError:
        missing_hash_rejected = True
    email = analyse("ACSI-2026-EVAL", initial + [artifact("phishing_email_headers.json", "email_headers")], model)
    dns = analyse("ACSI-2026-EVAL", initial + [artifact("phishing_dns.csv", "dns")], model)
    invalid_json = dict(artifact("phishing_dns.csv", "dns"), id="invalid", name="invalid.json", text="{bad json")
    invalid_json["sha256"] = hashlib.sha256(invalid_json["text"].encode()).hexdigest()
    malformed = analyse("ACSI-2026-EVAL", initial + [invalid_json], model)
    rejected_schema = False
    try:
        AnalysisRequest.model_validate({"caseId": "abc", "artifacts": [{"id": "x", "name": "x", "type": "executable", "text": "x"}]})
    except ValidationError:
        rejected_schema = True
    warm = []
    for _ in range(5):
        t = time.perf_counter()
        analyse("ACSI-2026-EVAL", initial, model)
        warm.append(time.perf_counter() - t)
    raws = [(SAMPLES / name).read_bytes() for name in
            ("phishing_endpoint_auth.csv", "phishing_firewall.csv", "phishing_ids.jsonl")]
    hashes = []
    for _ in range(1000):
        t = time.perf_counter_ns()
        for raw in raws:
            hashlib.sha256(raw).hexdigest()
        hashes.append((time.perf_counter_ns() - t) / 1e6)
    return {
        "initial": {"confidence": original["confidence"]["overall"], "coverage": original["confidence"]["evidenceCoverage"],
                    "provenance": original["confidence"]["provenanceIntegrity"], "recommendations": [x["type"] for x in original["recommendations"]],
                    "events": len(original["events"])},
        "tamper": {"rejected": tamper_rejected, "missing_hash_rejected": missing_hash_rejected, "error": tamper_error},
        "email_added": {"confidence": email["confidence"]["overall"], "coverage": email["confidence"]["evidenceCoverage"],
                        "recommendations": [x["type"] for x in email["recommendations"]]},
        "dns_added": {"confidence": dns["confidence"]["overall"], "coverage": dns["confidence"]["evidenceCoverage"],
                      "recommendations": [x["type"] for x in dns["recommendations"]]},
        "invalid": {"schema_rejected": rejected_schema, "parse_error": malformed["artifacts"][-1]["parseError"],
                    "invalid_rows": malformed["artifacts"][-1]["rowCount"], "other_events_preserved": len(malformed["events"]) == len(original["events"])},
        "timing": {"first_analysis_s": first_seconds, "warm_analysis_s": warm,
                   "warm_median_s": statistics.median(warm), "sha256_total_bytes": sum(map(len, raws)),
                   "sha256_three_file_median_ms": statistics.median(hashes)},
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    frame = pd.read_csv(DATA).dropna(subset=["text", "event_type", "source_type", "status", "label"])
    frame = frame.drop_duplicates().reset_index(drop=True)
    train, val, test = split_indices(frame)
    labels = frame.label.to_numpy()
    texts = frame.text.astype(str).tolist()
    # Baseline is trained only on train text: no test-fitted vocabulary or IDF.
    tfidf = TfidfVectorizer(ngram_range=(1, 2), max_features=2000)
    x_train = tfidf.fit_transform([texts[i] for i in train])
    rf = RandomForestClassifier(n_estimators=100, max_depth=6, random_state=42, n_jobs=1)
    rf.fit(x_train, labels[train])
    baseline = {name: metrics(labels[idx], rf.predict(tfidf.transform([texts[i] for i in idx])))
                for name, idx in (("validation", val), ("test", test))}
    engine = EmbeddingEngine()
    embeddings = engine.encode(texts, batch_size=16)
    events = [{"event_type": row.event_type, "message": row.text, "status": row.status,
               "source_type": row.source_type, "src_ip": "", "dst_ip": "", "domain": "", "url": ""}
              for row in frame.itertuples(index=False)]
    structured = np.vstack([structured_features(event) for event in events])
    features = np.hstack([embeddings, structured]).astype(np.float32)
    class_to_int = {c: i for i, c in enumerate(CLASSES)}
    target = np.array([class_to_int[label] for label in labels])
    model = xgboost.XGBClassifier(n_estimators=90, max_depth=3, learning_rate=0.08,
                                  subsample=0.9, colsample_bytree=0.8, objective="multi:softprob",
                                  eval_metric="mlogloss", random_state=42, n_jobs=1, tree_method="hist")
    model.fit(features[train], target[train])
    proposed = {name: metrics(labels[idx], np.array(CLASSES)[model.predict(features[idx]).astype(int)])
                for name, idx in (("validation", val), ("test", test))}
    info = {"python": sys.version.split()[0], "platform": platform.platform(), "processor": platform.processor(),
            "torch": torch.__version__, "transformers": transformers.__version__, "xgboost": xgboost.__version__,
            "sklearn": sklearn.__version__, "cpu_count": os.cpu_count(), "ram_bytes": None}
    try:
        import psutil
        info["ram_bytes"] = psutil.virtual_memory().total
    except ImportError:
        pass
    output = {"source": str(DATA), "dataset_sha256": hashlib.sha256(DATA.read_bytes()).hexdigest(),
              "rows_after_preprocessing": len(frame), "labels": CLASSES,
              "split": {name: {"indices": idx.tolist(), "n": len(idx), "classes": frame.label.iloc[idx].value_counts().to_dict(),
                               "event_type_groups": sorted(set(frame.event_type.iloc[idx]))}
                        for name, idx in (("train", train), ("validation", val), ("test", test))},
              "baseline_tfidf_random_forest": baseline, "proposed_distilbert_xgboost": proposed,
              "model_parameters": {key: model.get_params()[key] for key in
                                   ("n_estimators", "max_depth", "learning_rate", "subsample", "colsample_bytree",
                                    "objective", "eval_metric", "random_state", "n_jobs", "tree_method")},
              "environment": info, "security": security_experiments()}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(output, indent=2, default=str, allow_nan=False))
    print(json.dumps({"baseline_test": baseline["test"], "proposed_test": proposed["test"], "security": output["security"]}, indent=2))


if __name__ == "__main__":
    main()
