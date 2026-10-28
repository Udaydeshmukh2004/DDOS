"""
IntelliShield SDN — Accuracy and Metric Verification Audit Script
Traces predictions, ground-truth windows, and confusion counts directly.
"""

import sys
import os

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from evaluation.experiment_windows import load_experiment_windows, parse_ts, MONITOR_INTERVAL_DEFAULT
from evaluation.csv_log_io import load_csv_rows, KNOWN_CSV_HEADERS
from evaluation.ieee_metrics import POSITIVE_PREDICTION, compute_classification_metrics

def main():
    logs_dir = os.path.join(_ROOT, "logs")
    windows = load_experiment_windows(logs_dir)
    print(f"Loaded {len(windows)} attack windows from {logs_dir}:")
    for idx, w in enumerate(windows, 1):
        print(f"  [{idx:02d}] {w.scenario:15s}: {w.attack_start} -> {w.attack_stop} (duration: {w.duration_sec:.1f}s, source={w.source})")

    pred_path = os.path.join(logs_dir, "ml_predictions.csv")
    rows = load_csv_rows(pred_path, fallback_headers=KNOWN_CSV_HEADERS.get("ml_predictions.csv"))
    print(f"\nLoaded {len(rows)} ML predictions from {pred_path}:")
    
    tp = fp = tn = fn = 0
    records = []
    for i, r in enumerate(rows, 1):
        ts = parse_ts(r.get("timestamp", ""))
        status = str(r.get("status", "")).strip()
        pred_pos = status.upper() in POSITIVE_PREDICTION
        actual_pos = any(w.contains(ts, pad_sec=MONITOR_INTERVAL_DEFAULT) for w in windows)
        
        if pred_pos and actual_pos:
            tp += 1
            res = "TP"
        elif pred_pos and not actual_pos:
            fp += 1
            res = "FP"
        elif not pred_pos and not actual_pos:
            tn += 1
            res = "TN"
        else:
            fn += 1
            res = "FN"
            
        records.append({
            "idx": i, "ts": ts, "status": status,
            "pred_pos": pred_pos, "actual_pos": actual_pos,
            "res": res, "hint": r.get("attack_type_hint", ""),
            "confidence": r.get("confidence", ""),
            "iso_score": r.get("iso_score", ""),
            "packet_rate": r.get("packet_rate_mean", "")
        })
        print(f"  Row {i:02d}: {ts} | Pred={status:10s} (pos={str(pred_pos):5s}) | Actual={str(actual_pos):5s} | Result={res:2s} | Hint={r.get('attack_type_hint',''):15s} | Rate={r.get('packet_rate_mean','')}")

    total = tp + fp + tn + fn
    acc = (tp + tn) / total if total else 0
    prec = tp / (tp + fp) if (tp + fp) else 0
    rec = tp / (tp + fn) if (tp + fn) else 0
    f1 = (2 * prec * rec) / (prec + rec) if (prec + rec) else 0
    fpr = fp / (fp + tn) if (fp + tn) else 0
    spec = tn / (tn + fp) if (tn + fp) else 0
    bal_acc = (rec + spec) / 2

    print("\n" + "=" * 60)
    print("  CONFUSION MATRIX & METRICS RECALCULATION")
    print("=" * 60)
    print(f"  Total Cycles (N)       : {total}")
    print(f"  True Positives (TP)    : {tp}")
    print(f"  False Positives (FP)   : {fp}")
    print(f"  True Negatives (TN)    : {tn}")
    print(f"  False Negatives (FN)   : {fn}")
    print(f"  Positive Condition (P) : {tp + fn}  (Ground-Truth Attack cycles)")
    print(f"  Negative Condition (N) : {tn + fp}  (Ground-Truth Benign cycles)")
    print(f"  Predicted Positive     : {tp + fp}  (Detector flagged ATTACK/SUSPICIOUS)")
    print(f"  Predicted Negative     : {tn + fn}  (Detector flagged NORMAL)")
    print("-" * 60)
    print(f"  Accuracy               : {acc:.4f} ({acc*100:.2f}%)")
    print(f"  Precision (PPV)        : {prec:.4f} ({prec*100:.2f}%)")
    print(f"  Recall (Sensitivity)   : {rec:.4f} ({rec*100:.2f}%)")
    print(f"  F1-Score               : {f1:.4f} ({f1*100:.2f}%)")
    print(f"  False Positive Rate    : {fpr:.4f} ({fpr*100:.2f}%)")
    print(f"  Specificity (TNR)      : {spec:.4f} ({spec*100:.2f}%)")
    print(f"  Balanced Accuracy      : {bal_acc:.4f} ({bal_acc*100:.2f}%)")
    print("=" * 60)

if __name__ == "__main__":
    main()

