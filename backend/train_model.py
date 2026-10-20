from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder

from ml import EMBEDDING_MODEL, MODEL_DIR, STRUCTURED_FEATURES, EmbeddingEngine, structured_features


ROOT = Path(__file__).resolve().parent.parent
DATA_PATH = ROOT / "backend" / "data" / "training_events.csv"
RANDOM_STATE = 42


def main() -> None:
    print("Loading labelled training events...", flush=True)
    data = pd.read_csv(DATA_PATH)
    engine = EmbeddingEngine()
    events = [
        {
            "event_type": row.event_type,
            "message": row.text,
            "status": row.status,
            "source_type": row.source_type,
            "src_ip": "",
            "dst_ip": "",
            "domain": "",
            "url": "",
        }
        for row in data.itertuples(index=False)
    ]
    print(f"Generating DistilBERT embeddings for {len(data)} events...", flush=True)
    embeddings = engine.encode(data["text"].tolist(), batch_size=128)
    import xgboost as xgb
    structured = np.vstack([structured_features(event) for event in events])
    features = np.hstack([embeddings, structured]).astype(np.float32)
    encoder = LabelEncoder()
    labels = encoder.fit_transform(data["label"])
    x_train, x_test, y_train, y_test = train_test_split(
        features, labels, test_size=0.25, random_state=RANDOM_STATE, stratify=labels
    )
    model = xgb.XGBClassifier(
        n_estimators=90,
        max_depth=3,
        learning_rate=0.08,
        subsample=0.9,
        colsample_bytree=0.8,
        objective="multi:softprob",
        eval_metric="mlogloss",
        random_state=RANDOM_STATE,
        n_jobs=1,
        tree_method="hist",
    )
    print("Training XGBoost classifier...", flush=True)
    model.fit(x_train, y_train)
    predictions = model.predict(x_test)
    report = classification_report(y_test, predictions, target_names=encoder.classes_, output_dict=True, zero_division=0)
    metrics = {
        "dataset": str(DATA_PATH.relative_to(ROOT)),
        "samples": int(len(data)),
        "class_distribution": {key: int(value) for key, value in data["label"].value_counts().sort_index().items()},
        "train_samples": int(len(y_train)),
        "test_samples": int(len(y_test)),
        "test_fraction": 0.25,
        "random_state": RANDOM_STATE,
        "accuracy": round(float(accuracy_score(y_test, predictions)), 4),
        "macro_precision": round(float(report["macro avg"]["precision"]), 4),
        "macro_recall": round(float(report["macro avg"]["recall"]), 4),
        "macro_f1": round(float(report["macro avg"]["f1-score"]), 4),
        "confusion_matrix": confusion_matrix(y_test, predictions).tolist(),
        "classification_report": report,
    }
    MODEL_DIR.mkdir(exist_ok=True)
    model.save_model(MODEL_DIR / "event_classifier.json")
    metadata = {
        "model": "XGBoost XGBClassifier",
        "classes": encoder.classes_.tolist(),
        "embedding_model": EMBEDDING_MODEL,
        "embedding_dimension": engine.dimension,
        "pooling": "attention-mask mean pooling over last hidden state",
        "max_tokens": 128,
        "structured_features": STRUCTURED_FEATURES,
        "feature_count": int(features.shape[1]),
        "metrics": metrics,
    }
    (MODEL_DIR / "metadata.json").write_text(json.dumps(metadata, indent=2))
    print(json.dumps(metrics, indent=2))


if __name__ == "__main__":
    main()
