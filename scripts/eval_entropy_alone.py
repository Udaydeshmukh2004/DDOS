"""
Evaluate Entropy Detector alone on the 24 cycles
"""
import csv, os, sys
from datetime import datetime

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
from evaluation.experiment_windows import load_experiment_windows, parse_ts, MONITOR_INTERVAL_DEFAULT

def main():
    windows = load_experiment_windows("logs")
    with open("logs/entropy_logs.csv") as f:
        ent_rows = list(csv.DictReader(f))

    # Filter to the same time span as ml_predictions.csv (2026-10-22 19:46:02 to 19:48:34)
    start_ts = parse_ts("2026-10-22 19:46:00")
    stop_ts = parse_ts("2026-10-22 19:48:40")

    filtered = [r for r in ent_rows if start_ts <= parse_ts(r["timestamp"]) <= stop_ts]
    print(f"Entropy rows in time span: {len(filtered)}")

    tp = fp = tn = fn = 0
    for r in filtered:
        ts = parse_ts(r["timestamp"])
        actual_pos = any(w.contains(ts, pad_sec=MONITOR_INTERVAL_DEFAULT) for w in windows)
        # Status ALERT or WARNING is positive
        pred_pos = r["status"].upper() in ("ALERT", "WARNING")
        if pred_pos and actual_pos:
            tp += 1
        elif pred_pos and not actual_pos:
            fp += 1
        elif not pred_pos and not actual_pos:
            tn += 1
        else:
            fn += 1
        print(f"Entropy @ {ts}: status={r['status']}, score={r.get('entropy_score')}, pred_pos={pred_pos}, actual_pos={actual_pos}")

    total = tp + fp + tn + fn
    print(f"\nEntropy Alone -> TP={tp}, FP={fp}, TN={tn}, FN={fn}, Total={total}")
    if total:
        acc = (tp + tn) / total
        rec = tp / (tp + fn) if (tp + fn) else 0
        prec = tp / (tp + fp) if (tp + fp) else 0
        fpr = fp / (fp + tn) if (fp + tn) else 0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0
        print(f"Accuracy: {acc:.4f}, Recall: {rec:.4f}, Precision: {prec:.4f}, F1: {f1:.4f}, FPR: {fpr:.4f}")

if __name__ == "__main__":
    main()

