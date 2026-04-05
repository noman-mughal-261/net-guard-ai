#!/usr/bin/env python3
"""Verify NetGuard ML artifact folder before starting the API."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description="Check ML artifact directory layout.")
    parser.add_argument(
        "dir",
        nargs="?",
        default=os.environ.get("NETGUARD_ARTIFACT_DIR", ""),
        help="Artifact directory (default: NETGUARD_ARTIFACT_DIR or repo ml/artifacts)",
    )
    parser.add_argument(
        "--model-filename",
        default=os.environ.get("NETGUARD_MODEL_FILENAME", "model.pkl"),
        help="Classifier filename inside the artifact dir",
    )
    args = parser.parse_args()
    if not args.dir:
        root = Path(__file__).resolve().parents[1]
        d = root / "ml" / "artifacts"
    else:
        d = Path(args.dir)
    model = d / args.model_filename
    others = ["scaler.pkl", "label_encoder.pkl", "feature_names.json"]
    ok = True
    if not d.is_dir():
        print(f"ERROR: not a directory: {d}", file=sys.stderr)
        return 1
    if not model.exists():
        print(f"MISSING: {model}", file=sys.stderr)
        ok = False
    for name in others:
        p = d / name
        if not p.exists():
            print(f"MISSING: {p}", file=sys.stderr)
            ok = False
    if ok:
        with open(d / "feature_names.json", encoding="utf-8") as f:
            names = json.load(f)
        print(f"OK: {d}")
        print(f"  model: {model.name}")
        print(f"  features: {len(names)} columns")
        return 0
    print(
        "\nFix: copy netguard_rf_model.pkl (or rename to model.pkl), scaler.pkl, "
        "label_encoder.pkl, and feature_names.json from the same training run into this folder, "
        "or set NETGUARD_ARTIFACT_DIR / NETGUARD_MODEL_FILENAME.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
