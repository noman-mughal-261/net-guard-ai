"""
Train NetGuard AI classifier on Edge-IIoTset (or compatible CSV)
using XGBoost.

Set EDGE_IIOTSET_CSV to your ML-EdgeIIoT-dataset.csv path.
If unset, uses ../data/sample_flow_features.csv for a demo run.

Outputs:
    model.pkl
    imputer.pkl
    label_encoder.pkl
    feature_names.json
    model_metrics.json
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
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier


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
    for column in LABEL_CANDIDATES:
        if column in df.columns:
            return column

    raise ValueError(
        f"No label column found. Tried {LABEL_CANDIDATES}. "
        f"Columns: {list(df.columns)[:30]}..."
    )


def normalize_labels(series: pd.Series) -> pd.Series:
    def one(value: object) -> str:
        value_str = str(value).strip()

        if value_str in RAW_TO_CLASS:
            return RAW_TO_CLASS[value_str]

        normalized = value_str.lower().replace(" ", "_")

        for key, mapped_value in RAW_TO_CLASS.items():
            if key.lower() == normalized:
                return mapped_value

        if "ddos" in normalized:
            return "DDoS"

        if "dos" in normalized and "ddos" not in normalized:
            return "DoS"

        if "finger" in normalized or (
            "port" in normalized and "scan" in normalized
        ):
            return "PortScan"

        if "password" in normalized or "brute" in normalized:
            return "Brute_Force"

        if "normal" in normalized or value_str == "0":
            return "Normal"

        # Preserve the behavior of the original pipeline.
        return "DoS"

    return series.map(one)


def build_xy(
    df: pd.DataFrame,
    label_col: str,
    feature_cols: list[str],
) -> tuple[pd.DataFrame, np.ndarray]:

    y_raw = df[label_col]
    y = normalize_labels(y_raw)

    missing = [
        column
        for column in feature_cols
        if column not in df.columns
    ]

    if missing:
        raise ValueError(
            f"CSV missing feature columns ({len(missing)}): "
            f"{missing[:8]}... "
            "Map Edge-IIoTset columns to names in "
            "shared/feature_columns.json or use sample CSV."
        )

    X = df[feature_cols].copy()

    return X, y.values


def evaluate(
    label_encoder: LabelEncoder,
    y_test: np.ndarray,
    y_pred: np.ndarray,
) -> dict:

    labels = label_encoder.classes_.tolist()

    accuracy = float(
        accuracy_score(y_test, y_pred)
    )

    f1_weighted = float(
        f1_score(
            y_test,
            y_pred,
            average="weighted",
            zero_division=0,
        )
    )

    cm = confusion_matrix(
        y_test,
        y_pred,
        labels=range(len(labels)),
    ).tolist()

    report = classification_report(
        y_test,
        y_pred,
        labels=range(len(labels)),
        target_names=labels,
        output_dict=True,
        zero_division=0,
    )

    return {
        "accuracy": accuracy,
        "f1_weighted": f1_weighted,
        "confusion_matrix": cm,
        "labels": labels,
        "classification_report": report,
    }


def main() -> int:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--csv",
        default=os.environ.get(
            "EDGE_IIOTSET_CSV",
            str(DEFAULT_SAMPLE),
        ),
        help="Path to Edge-IIoTset ML CSV or sample CSV",
    )

    parser.add_argument(
        "--out",
        default=str(ARTIFACTS),
        help="Artifact directory",
    )

    args = parser.parse_args()

    csv_path = Path(args.csv)
    out_dir = Path(args.out)

    out_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    # ---------------------------------------------------------
    # Load feature definitions
    # ---------------------------------------------------------

    feature_cols = load_feature_list()

    if not csv_path.exists():
        print(
            f"CSV not found: {csv_path}",
            file=sys.stderr,
        )
        return 1

    print(f"Loading dataset: {csv_path}")

    df = pd.read_csv(
        csv_path,
        low_memory=False,
    )

    print(f"Dataset shape: {df.shape}")

    # ---------------------------------------------------------
    # Detect label
    # ---------------------------------------------------------

    label_col = detect_label_column(df)

    print(f"Label column: {label_col}")

    # ---------------------------------------------------------
    # Build X/y
    # ---------------------------------------------------------

    X, y = build_xy(
        df,
        label_col,
        feature_cols,
    )

    # Convert all features to numeric.
    for column in X.columns:
        X[column] = pd.to_numeric(
            X[column],
            errors="coerce",
        )

    # ---------------------------------------------------------
    # Encode labels
    # ---------------------------------------------------------

    label_encoder = LabelEncoder()

    y_encoded = label_encoder.fit_transform(y)

    print(
        "Classes:",
        label_encoder.classes_.tolist(),
    )

    # ---------------------------------------------------------
    # Train/test split BEFORE fitting imputer
    # ---------------------------------------------------------

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y_encoded,
        test_size=0.2,
        random_state=42,
        stratify=y_encoded,
    )

    # ---------------------------------------------------------
    # Imputation
    # ---------------------------------------------------------

    imputer = SimpleImputer(
        strategy="median"
    )

    X_train = imputer.fit_transform(
        X_train.astype(np.float64)
    )

    X_test = imputer.transform(
        X_test.astype(np.float64)
    )

    # ---------------------------------------------------------
    # XGBoost
    # ---------------------------------------------------------

    num_classes = len(
        label_encoder.classes_
    )

    clf = XGBClassifier(
        n_estimators=500,
        max_depth=8,
        learning_rate=0.05,
        subsample=0.8,
        colsample_bytree=0.8,

        objective="multi:softprob",
        num_class=num_classes,

        eval_metric="mlogloss",

        random_state=42,
        n_jobs=-1,

        tree_method="hist",
    )

    print("Training XGBoost...")

    clf.fit(
        X_train,
        y_train,
        eval_set=[
            (X_test, y_test)
        ],
        verbose=False,
    )

    # ---------------------------------------------------------
    # Evaluate
    # ---------------------------------------------------------

    y_pred = clf.predict(X_test)

    metrics = evaluate(
        label_encoder,
        y_test,
        y_pred,
    )

    # ---------------------------------------------------------
    # Save artifacts
    # ---------------------------------------------------------

    joblib.dump(
        clf,
        out_dir / "model.pkl",
    )

    joblib.dump(
        imputer,
        out_dir / "imputer.pkl",
    )

    joblib.dump(
        label_encoder,
        out_dir / "label_encoder.pkl",
    )

    with open(
        out_dir / "feature_names.json",
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            feature_cols,
            f,
            indent=2,
        )

    with open(
        out_dir / "model_metrics.json",
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            metrics,
            f,
            indent=2,
        )

    # ---------------------------------------------------------
    # Print results
    # ---------------------------------------------------------

    print()
    print("=" * 60)
    print("XGBoost training complete")
    print("=" * 60)

    print(
        f"Accuracy:    {metrics['accuracy']:.4f}"
    )

    print(
        f"Weighted F1: {metrics['f1_weighted']:.4f}"
    )

    print(
        "Classes:",
        metrics["labels"],
    )

    print()
    print(
        json.dumps(
            metrics["classification_report"],
            indent=2,
        )
    )

    print()
    print(
        f"Artifacts saved to: {out_dir}"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())