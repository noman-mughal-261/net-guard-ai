"""
Send CICFlowMeter-style flow features to NetGuard AI POST /api/analyze.

Usage:
  python ingest_flow_to_api.py --url http://localhost:8000 --token demo-token-user@example.com --csv path/to/flows.csv
  python ingest_flow_to_api.py --url http://localhost:8000 --json path/to/one_flow.json

For live capture (contiuuous sniff -> same /api/analyze endpoint), use capture_live_flows.py.
Set --token or NETGUARD_TOKEN to the login token (same as Authorization: Bearer after login).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import httpx
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
FEATURES_PATH = ROOT / "shared" / "feature_columns.json"


def load_features() -> list[str]:
    with open(FEATURES_PATH, encoding="utf-8") as f:
        return json.load(f)


def row_to_payload(row: dict, features: list[str], source_ip: str | None) -> dict:
    feat = {k: float(row[k]) for k in features if k in row and pd.notna(row.get(k))}
    missing = [k for k in features if k not in feat]
    if missing:
        raise ValueError(f"Row missing features: {missing[:8]}...")
    return {"features": feat, "source_ip": source_ip or row.get("source_ip")}


def _headers(token: str | None) -> dict[str, str]:
    h: dict[str, str] = {}
    if token:
        t = token.strip()
        if not t.lower().startswith("bearer "):
            t = f"Bearer {t}"
        h["Authorization"] = t
    return h


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--url", default="http://127.0.0.1:8000", help="Backend base URL")
    p.add_argument(
        "--token",
        default=os.environ.get("NETGUARD_TOKEN", ""),
        help="Login token (e.g. demo-token-user@domain.com) or set NETGUARD_TOKEN",
    )
    p.add_argument("--csv", help="CSV of flow rows")
    p.add_argument("--json", help="Single flow as JSON object of features (+ optional source_ip)")
    p.add_argument("--limit", type=int, default=50, help="Max rows from CSV")
    args = p.parse_args()
    features = load_features()
    base = args.url.rstrip("/")
    hdr = _headers(args.token or None)

    if args.json:
        with open(args.json, encoding="utf-8") as f:
            data = json.load(f)
        src = data.pop("source_ip", None)
        body = {"features": {k: float(data[k]) for k in features}, "source_ip": src}
        r = httpx.post(f"{base}/api/analyze", json=body, headers=hdr, timeout=60.0)
        print(r.status_code, r.text)
        return 0 if r.is_success else 1

    if not args.csv:
        print("Provide --csv or --json", file=sys.stderr)
        return 2

    df = pd.read_csv(args.csv, low_memory=False)
    n = 0
    for _, row in df.head(args.limit).iterrows():
        try:
            body = row_to_payload(row.to_dict(), features, row.get("source_ip"))
        except ValueError as e:
            print("skip row:", e)
            continue
        r = httpx.post(f"{base}/api/analyze", json=body, headers=hdr, timeout=60.0)
        print(r.status_code, r.json() if r.headers.get("content-type", "").startswith("application/json") else r.text)
        n += 1
    print(f"Sent {n} flows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
