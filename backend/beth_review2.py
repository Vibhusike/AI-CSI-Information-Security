"""Reproducible BETH host-held-out Review 2 experiment; downloads are never committed.

Run from the repository root: PYTHONPATH=backend .venv/bin/python backend/beth_review2.py
The frozen DistilBERT extractor is the project's existing backend.ml. This is an
experimental binary ``evil`` model, separate from the three-class demo model.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import platform
import time
import urllib.request
import zipfile
from collections import Counter
from pathlib import Path

import numpy as np
import pandas as pd
import sklearn
import torch
import transformers
import xgboost
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, confusion_matrix, precision_recall_fscore_support
from sklearn.pipeline import make_pipeline

from ml import EMBEDDING_MODEL, EmbeddingEngine, structured_features

ROOT = Path(__file__).resolve().parent.parent
CONFIG = json.loads((ROOT / "backend" / "beth_config.json").read_text())
SEED = CONFIG["seed"]
COLUMNS = ["timestamp", "processName", "eventName", "args", "userId", "argsNum", "returnValue", "sus", "evil"]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def obtain_dataset(path: Path, download: bool) -> None:
    if not path.exists():
        if not download:
            raise FileNotFoundError(f"BETH ZIP missing: {path}; pass --download")
        path.parent.mkdir(parents=True, exist_ok=True)
        request = urllib.request.Request(CONFIG["dataset_url"], headers={"User-Agent": "AI-CSI-Review2/1.0"})
        with urllib.request.urlopen(request, timeout=120) as source, path.open("wb") as target:
            while block := source.read(1024 * 1024):
                target.write(block)
    actual = sha256_file(path)
    if actual != CONFIG["zip_sha256"]:
        raise ValueError(f"Dataset ZIP SHA-256 mismatch: {actual}")


def load_host(archive: zipfile.ZipFile, host: str) -> pd.DataFrame:
    name = f"labelled_2021may-ip-10-100-1-{host}.csv"
    with archive.open(name) as source:
        data = pd.read_csv(source, usecols=COLUMNS, dtype={key: "string" for key in COLUMNS if key != "timestamp"})
    before = len(data)
    data["timestamp"] = pd.to_numeric(data["timestamp"], errors="coerce")
    data = data.dropna(subset=["timestamp", "processName", "eventName", "evil"])
    data = data[data["evil"].isin(["0", "1"])].copy()
    data["evil"] = data["evil"].astype("int8")
    print(f"host {host}: {before:,} source rows; {len(data):,} clean; {int(data.evil.sum()):,} evil", flush=True)
    return data


def event_text(row) -> str:
    """Convert structured BETH syscall fields into short event text; no labels/host/time."""
    try:
        args = ast.literal_eval(str(row.args))
    except (SyntaxError, ValueError, TypeError):
        args = []
    values = []
    if isinstance(args, list):
        for item in args[:4]:
            if isinstance(item, dict):
                value = str(item.get("value", ""))
                if value and not value.lstrip("-").isdigit():
                    values.append(f"{item.get('name', 'arg')} {value[:80]}")
    return f"process {row.processName} event {row.eventName} " + " ".join(values)


def prepare_sample(data: pd.DataFrame) -> pd.DataFrame:
    data = data.copy()
    data["text"] = [event_text(row) for row in data.itertuples(index=False)]
    data["processName"] = data["processName"].fillna("")
    data["eventName"] = data["eventName"].fillna("")
    return data


def sample_natural(data: pd.DataFrame, n: int, seed: int) -> pd.DataFrame:
    return data.sample(n=min(n, len(data)), random_state=seed).sort_index()


def build_splits(archive: zipfile.ZipFile) -> tuple[dict[str, pd.DataFrame], dict]:
    source = load_host(archive, "4")
    evil_times = source.loc[source.evil == 1, "timestamp"].sort_values()
    cutoff = float(evil_times.iloc[int(len(evil_times) * CONFIG["train_attack_fraction"])])
    early = source[source.timestamp < cutoff]
    late = source[source.timestamp >= cutoff]
    positive = early[early.evil == 1].sample(n=min(CONFIG["train_positive_n"], int(early.evil.sum())), random_state=SEED)
    negative = early[early.evil == 0].sample(n=CONFIG["train_negative_n"], random_state=SEED)
    train = prepare_sample(pd.concat([positive, negative]).sort_index())
    validation = prepare_sample(sample_natural(late, CONFIG["validation_n"], SEED + 1))
    counts = {"host_4_total": len(source), "host_4_evil": int(source.evil.sum()), "cutoff_seconds": cutoff,
              "early_rows": len(early), "early_evil": int(early.evil.sum()),
              "late_rows": len(late), "late_evil": int(late.evil.sum())}
    del source, early, late
    held_out = load_host(archive, "105")
    test = prepare_sample(sample_natural(held_out, CONFIG["test_n"], SEED + 2))
    counts.update({"host_105_total": len(held_out), "host_105_evil": int(held_out.evil.sum())})
    splits = {"train": train, "validation": validation, "test": test}
    for name, frame in splits.items():
        counts[name] = {"n": len(frame), "normal": int((frame.evil == 0).sum()), "evil": int(frame.evil.sum()),
                        "host": "4" if name != "test" else "105"}
    return splits, counts


def select_threshold(y_true, probabilities) -> tuple[float, float]:
    thresholds = np.linspace(0.01, 0.99, 99)
    scored = []
    for threshold in thresholds:
        pred = (probabilities >= threshold).astype(int)
        score = precision_recall_fscore_support(y_true, pred, average="binary", zero_division=0)[2]
        scored.append((float(score), float(threshold)))
    return max(scored, key=lambda x: (x[0], -x[1]))[1], max(x[0] for x in scored)


def score(y_true, probabilities, threshold: float) -> dict:
    pred = (probabilities >= threshold).astype(int)
    p, r, f, _ = precision_recall_fscore_support(y_true, pred, average="binary", zero_division=0)
    mp, mr, mf, _ = precision_recall_fscore_support(y_true, pred, average="macro", zero_division=0)
    return {"accuracy": float(accuracy_score(y_true, pred)), "precision_evil": float(p), "recall_evil": float(r),
            "f1_evil": float(f), "macro_precision": float(mp), "macro_recall": float(mr), "macro_f1": float(mf),
            "confusion_matrix_normal_evil": confusion_matrix(y_true, pred, labels=[0, 1]).tolist(),
            "predicted_evil": int(pred.sum())}


def evaluate_model(name: str, model, splits, results, x_values):
    start = time.perf_counter()
    model.fit(x_values["train"], splits["train"].evil.to_numpy())
    train_seconds = time.perf_counter() - start
    val_prob = model.predict_proba(x_values["validation"])[:, 1]
    threshold, val_best_f1 = select_threshold(splits["validation"].evil.to_numpy(), val_prob)
    start = time.perf_counter()
    test_prob = model.predict_proba(x_values["test"])[:, 1]
    test_seconds = time.perf_counter() - start
    results[name] = {"threshold_from_validation": threshold, "validation_best_f1_evil": val_best_f1,
                     "validation": score(splits["validation"].evil.to_numpy(), val_prob, threshold),
                     "test": score(splits["test"].evil.to_numpy(), test_prob, threshold),
                     "train_seconds": train_seconds, "test_predict_seconds": test_seconds,
                     "test_predict_ms_per_event": test_seconds * 1000 / len(test_prob)}
    print(name, json.dumps({k: results[name][k] for k in ("threshold_from_validation", "test", "train_seconds")}), flush=True)
    return model, test_prob


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--zip", type=Path, default=ROOT / "data" / "beth-v3.zip")
    parser.add_argument("--download", action="store_true")
    parser.add_argument("--output", type=Path, default=ROOT / "results" / "beth_review2_results.json")
    parser.add_argument("--device", choices=["cpu", "mps"], default="cpu")
    args = parser.parse_args()
    np.random.seed(SEED)
    torch.manual_seed(SEED)
    torch.set_num_threads(4)
    obtain_dataset(args.zip, args.download)
    with zipfile.ZipFile(args.zip) as archive:
        splits, counts = build_splits(archive)
    texts = {name: frame.text.tolist() for name, frame in splits.items()}
    labels = {name: frame.evil.to_numpy() for name, frame in splits.items()}
    results = {}
    tfidf = TfidfVectorizer(ngram_range=(1, 2), min_df=2, max_features=10000, sublinear_tf=True)
    x_tfidf = {"train": tfidf.fit_transform(texts["train"])}
    for name in ("validation", "test"):
        x_tfidf[name] = tfidf.transform(texts[name])
    evaluate_model("tfidf_random_forest", RandomForestClassifier(n_estimators=200, min_samples_leaf=2,
                   class_weight="balanced_subsample", random_state=SEED, n_jobs=4), splits, results, x_tfidf)
    evaluate_model("tfidf_logistic_regression", LogisticRegression(max_iter=1000, class_weight="balanced",
                   random_state=SEED), splits, results, x_tfidf)
    print("Encoding BETH event text with frozen DistilBERT...", flush=True)
    encoder = EmbeddingEngine(device=args.device, max_length=64)
    x_bert = {}
    encode_seconds = {}
    for name in ("train", "validation", "test"):
        start = time.perf_counter()
        embedding = encoder.encode(texts[name], batch_size=64)
        structured = np.vstack([structured_features({"event_type": row.eventName, "message": row.text,
                                "source_type": "edr"}) for row in splits[name].itertuples(index=False)])
        x_bert[name] = np.hstack([embedding, structured]).astype(np.float32)
        encode_seconds[name] = time.perf_counter() - start
        print(name, "embedding seconds", round(encode_seconds[name], 2), flush=True)
    model = xgboost.XGBClassifier(n_estimators=120, max_depth=4, learning_rate=0.08,
        subsample=0.9, colsample_bytree=0.8, objective="binary:logistic", eval_metric="logloss",
        tree_method="hist", n_jobs=4, random_state=SEED)
    model, test_prob = evaluate_model("distilbert_xgboost", model, splits, results, x_bert)
    results["distilbert_xgboost"]["encode_seconds"] = encode_seconds
    # TreeSHAP aggregates the 768 contextual dimensions; it is not token attribution.
    import shap
    start = time.perf_counter()
    explanation = shap.TreeExplainer(model)(x_bert["test"][:32])
    mean_abs = np.abs(explanation.values).mean(axis=0)
    top = np.argsort(mean_abs)[::-1][:10]
    feature_names = [f"embedding_{i}" for i in range(768)] + [
        "risk_keyword_count", "authentication_signal", "privilege_signal", "outbound_transfer_signal",
        "script_execution_signal", "malware_signal", "failure_status", "has_ip", "has_domain", "source_risk"]
    results["distilbert_xgboost"]["shap"] = {"sample_n": 32, "seconds": time.perf_counter() - start,
        "embedding_mean_abs_sum": float(mean_abs[:768].sum()),
        "structured_mean_abs_sum": float(mean_abs[768:].sum()),
        "top_features": [{"feature": feature_names[i], "mean_abs_shap": float(mean_abs[i])} for i in top]}
    output = {"dataset": {"name": "BETH labelled May 2021 host events", "source_url": CONFIG["source_url"],
        "zip_sha256": CONFIG["zip_sha256"], "label": "evil", "split": counts,
        "preprocessing": "Drop missing timestamp/process/event/label; exclude host, timestamp, sus, evil from features; parse up to four nonnumeric argument values; no cross-split fitting.",
        "sampling": "Fixed-seed stratified training sample; natural random validation/test samples. Host 105 exclusively test; host 4 chronological train/validation boundary at 70% of its confirmed malicious events."},
        "setup": {"python": platform.python_version(), "platform": platform.platform(), "processor": platform.processor(),
                  "torch": torch.__version__, "transformers": transformers.__version__, "xgboost": xgboost.__version__,
                  "sklearn": sklearn.__version__, "device": args.device, "seed": SEED,
                  "embedding_model": EMBEDDING_MODEL, "embedding_max_tokens": 64},
        "models": results, "tfidf_features": len(tfidf.vocabulary_)}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    model.save_model(args.output.parent / "beth_binary_xgboost.json")
    args.output.write_text(json.dumps(output, indent=2))
    print("Saved", args.output, flush=True)


if __name__ == "__main__":
    main()
