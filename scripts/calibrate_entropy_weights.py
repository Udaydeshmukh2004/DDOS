"""
Calibrate Entropy Weights & Adaptive Threshold on Experiment Data
"""
import csv, os, sys
import numpy as np

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
from evaluation.experiment_windows import load_experiment_windows, parse_ts, MONITOR_INTERVAL_DEFAULT

def main():
    windows = load_experiment_windows(os.path.join(_ROOT, "logs"))
    start_ts = parse_ts("2026-10-22 19:46:00")
    stop_ts = parse_ts("2026-10-22 19:48:40")

    with open(os.path.join(_ROOT, "logs", "entropy_logs.csv")) as f:
        rows = [r for r in csv.DictReader(f) if start_ts <= parse_ts(r["timestamp"]) <= stop_ts]

    # Test weight distributions
    weight_sets = {
        "Original_Weights": {"src": 0.30, "dst": 0.30, "packet": 0.15, "byte": 0.15, "flow": 0.10},
        "Load_Balanced_Weights": {"src": 0.20, "dst": 0.20, "packet": 0.25, "byte": 0.25, "flow": 0.10},
        "Volumetric_Focused_Weights": {"src": 0.15, "dst": 0.15, "packet": 0.30, "byte": 0.30, "flow": 0.10},
    }

    for w_name, weights in weight_sets.items():
        print(f"\n--- Testing {w_name} ---")
        scores = []
        actuals = []
        for r in rows:
            ts = parse_ts(r["timestamp"])
            actual = any(w.contains(ts, pad_sec=MONITOR_INTERVAL_DEFAULT) for w in windows)
            score = (
                weights["src"] * float(r["src_entropy"]) +
                weights["dst"] * float(r["dst_entropy"]) +
                weights["packet"] * float(r["packet_entropy"]) +
                weights["byte"] * float(r["byte_entropy"]) +
                weights["flow"] * float(r["flow_entropy"])
            )
            scores.append(score)
            actuals.append(actual)

        # Baseline on normal samples
        normal_scores = [s for s, a in zip(scores, actuals) if not a]
        attack_scores = [s for s, a in zip(scores, actuals) if a]
        print(f"Normal Scores: mean={np.mean(normal_scores):.4f}, min={np.min(normal_scores):.4f}, std={np.std(normal_scores):.4f}")
        print(f"Attack Scores: mean={np.mean(attack_scores):.4f}, min={np.min(attack_scores):.4f}, std={np.std(attack_scores):.4f}")

        # Grid search threshold
        best_t, best_f1, best_rec, best_prec = 0, 0, 0, 0
        for t in np.arange(0.60, 0.95, 0.01):
            tp = sum(1 for s, a in zip(scores, actuals) if s < t and a)
            fp = sum(1 for s, a in zip(scores, actuals) if s < t and not a)
            tn = sum(1 for s, a in zip(scores, actuals) if s >= t and not a)
            fn = sum(1 for s, a in zip(scores, actuals) if s >= t and a)
            rec = tp / (tp + fn) if (tp + fn) > 0 else 0
            prec = tp / (tp + fp) if (tp + fp) > 0 else 0
            f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0
            if f1 > best_f1:
                best_f1, best_t, best_rec, best_prec = f1, t, rec, prec

        print(f"Optimal Threshold={best_t:.2f} -> Recall={best_rec*100:.1f}%, Precision={best_prec*100:.1f}%, F1={best_f1*100:.1f}%")

if __name__ == "__main__":
    main()

