#!/usr/bin/env python3
"""
HTTP checks against a running NetGuard API (Docker Compose or local uvicorn).

Usage:
  python scripts/e2e_test.py
  python scripts/e2e_test.py --base-url http://127.0.0.1:8000
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any


def _get(
    url: str, timeout: float = 30.0, *, expect_json: bool = True
) -> tuple[int, Any]:
    accept = "application/json" if expect_json else "*/*"
    req = urllib.request.Request(url, method="GET", headers={"Accept": accept})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode()
        if not expect_json:
            return resp.status, body
        return resp.status, json.loads(body) if body else None


def _post(url: str, payload: dict, timeout: float = 60.0) -> tuple[int, Any]:
    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode()
        return resp.status, json.loads(body) if body else None


def _analyze_body_from_sample(path: Path) -> dict[str, Any]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    source_ip = raw.pop("source_ip", None)
    return {"source_ip": source_ip, "features": raw}


def main() -> int:
    parser = argparse.ArgumentParser(description="NetGuard API end-to-end HTTP checks")
    parser.add_argument("--base-url", default="http://127.0.0.1:8000", help="API root URL")
    parser.add_argument(
        "--sample-flow",
        default="",
        help="Path to sample_single_flow.json (default: repo data/sample_single_flow.json)",
    )
    parser.add_argument(
        "--frontend-url",
        default="",
        help="If set (e.g. http://127.0.0.1:8080), GET / and expect 200",
    )
    args = parser.parse_args()
    base = args.base_url.rstrip("/")
    root = Path(__file__).resolve().parents[1]
    sample = Path(args.sample_flow) if args.sample_flow else root / "data" / "sample_single_flow.json"

    if not sample.is_file():
        print(f"ERROR: sample flow file not found: {sample}", file=sys.stderr)
        return 1

    checks: list[tuple[str, Callable[[], None]]] = []

    def check_health() -> None:
        code, data = _get(f"{base}/api/health")
        assert code == 200, f"health status {code}"
        assert isinstance(data, dict), data
        assert data.get("mongodb") is True, f"mongodb not ready: {data}"
        assert data.get("model_loaded") is True, f"model not loaded: {data}"

    checks.append(("GET /api/health", check_health))

    def check_analyze() -> None:
        body = _analyze_body_from_sample(sample)
        code, data = _post(f"{base}/api/analyze", body)
        assert code == 200, f"analyze status {code}: {data}"
        assert isinstance(data, dict), data
        assert "label" in data and "confidence" in data, data
        assert "log_id" in data, data

    checks.append(("POST /api/analyze", check_analyze))

    def check_logs() -> None:
        code, data = _get(f"{base}/api/logs?limit=5")
        assert code == 200, f"logs status {code}"
        assert isinstance(data, dict) and "items" in data, data

    checks.append(("GET /api/logs", check_logs))

    def check_model_performance() -> None:
        try:
            code, data = _get(f"{base}/api/model-performance")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                return
            raise
        assert code == 200, f"model-performance status {code}"
        assert isinstance(data, dict), data

    checks.append(("GET /api/model-performance (optional)", check_model_performance))

    def check_analytics() -> None:
        code, data = _get(f"{base}/api/analytics/summary")
        assert code == 200, f"analytics status {code}"
        assert isinstance(data, dict) and "threat_breakdown" in data, data

    checks.append(("GET /api/analytics/summary", check_analytics))

    if args.frontend_url.strip():
        fe = args.frontend_url.rstrip("/")

        def check_frontend() -> None:
            code, _data = _get(f"{fe}/", timeout=15.0, expect_json=False)
            assert code == 200, f"frontend status {code}"

        checks.append((f"GET {fe}/", check_frontend))

    failed = False
    for name, fn in checks:
        try:
            fn()
            print(f"OK  {name}")
        except Exception as e:
            print(f"FAIL {name}: {e}", file=sys.stderr)
            failed = True

    if failed:
        return 1
    print("All checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
