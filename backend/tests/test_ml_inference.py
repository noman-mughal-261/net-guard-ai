from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.config import get_settings
from app.ml_inference import MLService


@pytest.fixture(autouse=True)
def reset_settings_cache():
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def test_load_raises_when_artifacts_missing(monkeypatch, tmp_path):
    monkeypatch.setenv("NETGUARD_ARTIFACT_DIR", str(tmp_path))
    get_settings.cache_clear()
    svc = MLService()
    with pytest.raises(FileNotFoundError, match="Missing model artifacts"):
        svc.load()


def test_ml_service_load_and_predict():
    s = get_settings()
    d = Path(s["artifact_dir"])
    model = d / s["model_filename"]
    if not model.exists():
        pytest.skip(f"No model at {model}; run: python ml/train.py or set NETGUARD_ARTIFACT_DIR")
    with open(d / "feature_names.json", encoding="utf-8") as f:
        names: list[str] = json.load(f)
    features = {n: 0.0 for n in names}
    svc = MLService()
    svc.load()
    out = svc.predict_from_features(features)
    assert "label" in out
    assert "confidence" in out
    assert "probabilities" in out
    assert out["label"] in out["probabilities"]
