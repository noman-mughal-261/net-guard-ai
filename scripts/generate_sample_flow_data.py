"""Generate sample_flow_features.csv for demo training (CICFlowMeter-style columns)."""
from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
FEATURES = json.loads((ROOT / "shared" / "feature_columns.json").read_text(encoding="utf-8"))
OUT = ROOT / "data" / "sample_flow_features.csv"
RNG = np.random.default_rng(42)

CLASSES = ["Normal", "DoS", "DDoS", "PortScan", "Brute_Force"]


def row_for_class(label: str) -> dict:
    r = {f: 0.0 for f in FEATURES}
    if label == "Normal":
        r["flow_duration"] = float(RNG.integers(50, 5000))
        r["tot_fwd_pkts"] = float(RNG.integers(4, 80))
        r["tot_bwd_pkts"] = float(RNG.integers(4, 80))
        r["flow_pkts_s"] = float(RNG.uniform(1, 50))
        r["flow_bytes_s"] = float(RNG.uniform(500, 8000))
        r["syn_flag_cnt"] = float(RNG.integers(0, 2))
    elif label == "DDoS":
        r["flow_duration"] = float(RNG.integers(1, 200))
        r["tot_fwd_pkts"] = float(RNG.integers(200, 5000))
        r["tot_bwd_pkts"] = float(RNG.integers(0, 50))
        r["flow_pkts_s"] = float(RNG.uniform(500, 8000))
        r["flow_bytes_s"] = float(RNG.uniform(1e5, 2e6))
        r["syn_flag_cnt"] = float(RNG.integers(50, 500))
    elif label == "DoS":
        r["flow_duration"] = float(RNG.integers(10, 800))
        r["tot_fwd_pkts"] = float(RNG.integers(80, 800))
        r["flow_pkts_s"] = float(RNG.uniform(80, 1200))
        r["rst_flag_cnt"] = float(RNG.integers(5, 120))
    elif label == "PortScan":
        r["flow_duration"] = float(RNG.integers(1, 30))
        r["tot_fwd_pkts"] = float(RNG.integers(2, 12))
        r["tot_bwd_pkts"] = float(RNG.integers(0, 4))
        r["fin_flag_cnt"] = float(RNG.integers(1, 6))
        r["syn_flag_cnt"] = float(RNG.integers(1, 8))
        r["flow_iat_mean"] = float(RNG.uniform(0.001, 0.05))
    else:  # Brute_Force
        r["flow_duration"] = float(RNG.integers(2000, 120000))
        r["tot_fwd_pkts"] = float(RNG.integers(20, 400))
        r["tot_bwd_pkts"] = float(RNG.integers(20, 400))
        r["psh_flag_cnt"] = float(RNG.integers(10, 200))
        r["down_up_ratio"] = float(RNG.uniform(0.3, 3.0))
    for f in FEATURES:
        if r[f] == 0.0 and f not in (
            "flow_duration",
            "tot_fwd_pkts",
            "tot_bwd_pkts",
        ):
            r[f] = float(RNG.uniform(0, 1) * RNG.choice([0, 0.1, 1, 10]))
    r["attack_type"] = label
    return r


def main() -> None:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    per = 600
    for lab in CLASSES:
        for _ in range(per):
            rows.append(row_for_class(lab))
    df = pd.DataFrame(rows)
    df.to_csv(OUT, index=False)
    print(f"Wrote {len(df)} rows to {OUT}")


if __name__ == "__main__":
    main()
