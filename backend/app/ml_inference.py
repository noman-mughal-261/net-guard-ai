from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import joblib
import numpy as np

from .config import get_settings

_REQUIRED_FILES = ("model.pkl", "scaler.pkl", "label_encoder.pkl", "feature_names.json")


class MLService:
    def __init__(self) -> None:
        self._clf = None
        self._scaler = None
        self._le = None
        self._feature_names: list[str] = []
        self._loaded = False

    @property
    def is_loaded(self) -> bool:
        return self._loaded

    def load(self) -> None:
        if self._loaded:
            return
        d = Path(get_settings()["artifact_dir"])
        missing = [name for name in _REQUIRED_FILES if not (d / name).exists()]
        if missing:
            raise FileNotFoundError(
                f"Missing model artifacts in {d}: {missing}. "
                "Run training (e.g. python ml/train.py) or set NETGUARD_ARTIFACT_DIR "
                "to the folder that contains model.pkl, scaler.pkl, label_encoder.pkl, and feature_names.json."
            )
        self._clf = joblib.load(d / "model.pkl")
        self._scaler = joblib.load(d / "scaler.pkl")
        self._le = joblib.load(d / "label_encoder.pkl")
        with open(d / "feature_names.json", encoding="utf-8") as f:
            self._feature_names = json.load(f)
        self._loaded = True

    def predict_from_features(self, features: dict[str, Any]) -> dict[str, Any]:
        self.load()
        vec = []
        missing = []
        for name in self._feature_names:
            if name not in features:
                missing.append(name)
                vec.append(np.nan)
            else:
                vec.append(float(features[name]))
        if missing:
            raise ValueError(f"Missing features: {missing[:12]}{'...' if len(missing) > 12 else ''}")
        x = np.array(vec, dtype=np.float64).reshape(1, -1)
        x_s = self._scaler.transform(x)
        proba = self._clf.predict_proba(x_s)[0]
        idx = int(np.argmax(proba))
        label = str(self._le.inverse_transform([idx])[0])
        confidence = float(proba[idx])
        classes = [str(c) for c in self._le.classes_]
        probabilities = {classes[i]: float(proba[i]) for i in range(len(classes))}
        return {
            "label": label,
            "confidence": confidence,
            "probabilities": probabilities,
        }


ml_service = MLService()


def load_metrics() -> dict | None:
    p = Path(get_settings()["artifact_dir"]) / "model_metrics.json"
    if not p.exists():
        return None
    with open(p, encoding="utf-8") as f:
        return json.load(f)
