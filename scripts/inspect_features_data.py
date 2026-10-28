"""
Inspect ml_features.csv training set provenance and correlation with duration_mean
"""
import csv, os, sys
import numpy as np

def main():
    features_path = "logs/ml_features.csv"
    with open(features_path) as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    print(f"Total rows in ml_features.csv: {len(rows)}")
    labels = [int(float(r["label"])) for r in rows if r["label"] not in ("", "-1")]
    print(f"Labels: Normal(0)={labels.count(0)}, Attack(1)={labels.count(1)}")

    # Check timestamps span
    ts = [r["timestamp"] for r in rows if r.get("timestamp")]
    print(f"Time span: {min(ts)} -> {max(ts)}")

    # Check duration_mean distributions
    dur_normal = [float(r["duration_mean"]) for r in rows if r["label"] == "0"]
    dur_attack = [float(r["duration_mean"]) for r in rows if r["label"] == "1"]

    print(f"Normal duration_mean: min={min(dur_normal):.1f}, max={max(dur_normal):.1f}, mean={np.mean(dur_normal):.1f}")
    print(f"Attack duration_mean: min={min(dur_attack):.1f}, max={max(dur_attack):.1f}, mean={np.mean(dur_attack):.1f}")

    # Check packet_rate_mean distributions
    pr_normal = [float(r["packet_rate_mean"]) for r in rows if r["label"] == "0"]
    pr_attack = [float(r["packet_rate_mean"]) for r in rows if r["label"] == "1"]
    print(f"Normal packet_rate_mean: min={min(pr_normal):.2f}, max={max(pr_normal):.2f}, mean={np.mean(pr_normal):.2f}")
    print(f"Attack packet_rate_mean: min={min(pr_attack):.2f}, max={max(pr_attack):.2f}, mean={np.mean(pr_attack):.2f}")

if __name__ == "__main__":
    main()

