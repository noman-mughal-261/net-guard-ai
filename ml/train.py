"""
Train NetGuard AI classifier on Edge-IIoTset (or compatible CSV) using scikit-learn.

Set EDGE_IIOTSET_CSV to your ML-EdgeIIoT-dataset.csv path. If unset, uses
../data/sample_flow_features.csv for a demo pipeline run.

Outputs: model.pkl, scaler.pkl, label_encoder.pkl, feature_names.json, model_metrics.json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

ROOT = Path(__file__).resolve().parents[1]
SHARED = ROOT / "shared"
DEFAULT_SAMPLE = ROOT / "data" / "sample_flow_features.csv"
ARTIFACTS = ROOT / "ml" / "artifacts"

LABEL_CANDIDATES = [
    "attack_type",
    "Attack_type",
    "label",
    "Label",
    "Attack_label",
    "attack_label",
    "Attack category",
    "attack_category",
]

RAW_TO_CLASS = {
    "normal": "Normal",
    "benign": "Normal",
    "Normal": "Normal",
    "BACKDOOR": "DoS",
    "Backdoor": "DoS",
    "DDOS_HTTP": "DDoS",
    "DDOS_ICMP": "DDoS",
    "DDOS_TCP": "DDoS",
    "DDOS_UDP": "DDoS",
    "DDoS_HTTP": "DDoS",
    "DDoS_ICMP": "DDoS",
    "DDoS_TCP": "DDoS",
    "DDoS_UDP": "DDoS",
    "DOS_HTTP": "DoS",
    "DOS_TCP": "DoS",
    "DOS_UDP": "DoS",
    "DoS_HTTP": "DoS",
    "DoS_TCP": "DoS",
    "DoS_UDP": "DoS",
    "FINGERPRINTING": "PortScan",
    "Fingerprinting": "PortScan",
    "MITM": "DoS",
    "PASSWORD": "Brute_Force",
    "Password": "Brute_Force",
    "RANSOMWARE": "DoS",
    "Ransomware": "DoS",
    "SQL_INJECTION": "DoS",
    "SQL injection": "DoS",
    "UPLOADING": "DoS",
    "Uploading": "DoS",
    "XSS": "DoS",
}


def load_feature_list() -> list[str]:
    with open(SHARED / "feature_columns.json", encoding="utf-8") as f:
        return json.load(f)


def detect_label_column(df: pd.DataFrame) -> str:
    for c in LABEL_CANDIDATES:
        if c in df.columns:
            return c
    raise ValueError(
        f"No label column found. Tried {LABEL_CANDIDATES}. Columns: {list(df.columns)[:30]}..."
    )


def normalize_labels(series: pd.Series) -> pd.Series:
    def one(x: object) -> str:
        s = str(x).strip()
        if s in RAW_TO_CLASS:
            return RAW_TO_CLASS[s]
        low = s.lower().replace(" ", "_")
        for k, v in RAW_TO_CLASS.items():
            if k.lower() == low:
                return v
        if "ddos" in low:
            return "DDoS"
        if "dos" in low and "ddos" not in low:
            return "DoS"
        if "finger" in low or ("port" in low and "scan" in low):
            return "PortScan"
        if "password" in low or "brute" in low:
            return "Brute_Force"
        if "normal" in low or s == "0":
            return "Normal"
        return "DoS"

    return series.map(one)


def build_xy(
    df: pd.DataFrame,
    label_col: str,
    feature_cols: list[str],
) -> tuple[pd.DataFrame, np.ndarray]:
    y_raw = df[label_col]
    y = normalize_labels(y_raw)
    missing = [c for c in feature_cols if c not in df.columns]
    if missing:
        raise ValueError(
            f"CSV missing feature columns ({len(missing)}): {missing[:8]}... "
            "Map Edge-IIoTset columns to names in shared/feature_columns.json or use sample CSV."
        )
    X = df[feature_cols].copy()
    return X, y.values


def evaluate(le: LabelEncoder, y_test: np.ndarray, y_pred: np.ndarray) -> dict:
    labels = le.classes_.tolist()
    acc = float(accuracy_score(y_test, y_pred))
    f1w = float(f1_score(y_test, y_pred, average="weighted", zero_division=0))
    cm = confusion_matrix(y_test, y_pred).tolist()
    report = classification_report(
        y_test, y_pred, target_names=labels, output_dict=True, zero_division=0
    )
    return {
        "accuracy": acc,
        "f1_weighted": f1w,
        "confusion_matrix": cm,
        "labels": labels,
        "classification_report": report,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--csv",
        default=os.environ.get("EDGE_IIOTSET_CSV", str(DEFAULT_SAMPLE)),
        help="Path to Edge-IIoTset ML CSV or sample_flow_features.csv",
    )
    parser.add_argument("--out", default=str(ARTIFACTS), help="Artifact directory")
    args = parser.parse_args()
    csv_path = Path(args.csv)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    feature_cols = load_feature_list()
    if not csv_path.exists():
        print(f"CSV not found: {csv_path}", file=sys.stderr)
        return 1

    df = pd.read_csv(csv_path, low_memory=False)
    label_col = detect_label_column(df)
    X, y = build_xy(df, label_col, feature_cols)

    for c in X.columns:
        X[c] = pd.to_numeric(X[c], errors="coerce")

    le = LabelEncoder()
    y_enc = le.fit_transform(y)
    X_imp = SimpleImputer(strategy="median").fit_transform(X.values.astype(np.float64))
    scaler = StandardScaler()
    X_s = scaler.fit_transform(X_imp)

    X_train, X_test, y_train, y_test = train_test_split(
        X_s, y_enc, test_size=0.2, random_state=42, stratify=y_enc
    )

    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=22,
        min_samples_leaf=2,
        class_weight="balanced_subsample",
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)
    metrics = evaluate(le, y_test, y_pred)

    joblib.dump(clf, out_dir / "model.pkl")
    joblib.dump(scaler, out_dir / "scaler.pkl")
    joblib.dump(le, out_dir / "label_encoder.pkl")
    with open(out_dir / "feature_names.json", "w", encoding="utf-8") as f:
        json.dump(feature_cols, f, indent=2)
    with open(out_dir / "model_metrics.json", "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)

    print(json.dumps({"status": "ok", "artifacts": str(out_dir), "metrics": metrics}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
