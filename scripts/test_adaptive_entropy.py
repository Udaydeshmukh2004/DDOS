"""
Test Adaptive Entropy Detection on logs/entropy_logs.csv
"""
import csv
import os
import sys
import numpy as np

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

from evaluation.experiment_windows import load_experiment_windows, parse_ts, MONITOR_INTERVAL_DEFAULT

def main():
    windows = load_experiment_windows(os.path.join(_ROOT, "logs"))
    entropy_csv = os.path.join(_ROOT, "logs", "entropy_logs.csv")
    
    with open(entropy_csv, "r") as f:
        rows = list(csv.DictReader(f))
        
    start_ts = parse_ts("2026-10-22 19:46:00")
    stop_ts = parse_ts("2026-10-22 19:48:40")
    filtered = [r for r in rows if start_ts <= parse_ts(r["timestamp"]) <= stop_ts]
    
    print(f"Total cycles in test window: {len(filtered)}")
    
    # 1. Static Threshold (0.40) - Baseline
    tp_s = fp_s = tn_s = fn_s = 0
    for r in filtered:
        ts = parse_ts(r["timestamp"])
        actual_pos = any(w.contains(ts, pad_sec=MONITOR_INTERVAL_DEFAULT) for w in windows)
        score = float(r.get("entropy_score", 1.0))
        pred_pos = score < 0.40
        if pred_pos and actual_pos: tp_s += 1
        elif pred_pos and not actual_pos: fp_s += 1
        elif not pred_pos and not actual_pos: tn_s += 1
        else: fn_s += 1
        
    print(f"Static Threshold (0.40) -> TP={tp_s}, FP={fp_s}, TN={tn_s}, FN={fn_s}")
    rec_s = tp_s / (tp_s + fn_s) if (tp_s + fn_s) > 0 else 0
    prec_s = tp_s / (tp_s + fp_s) if (tp_s + fp_s) > 0 else 0
    f1_s = 2 * prec_s * rec_s / (prec_s + rec_s) if (prec_s + rec_s) > 0 else 0
    print(f"  Recall={rec_s*100:.1f}%, Precision={prec_s*100:.1f}%, F1={f1_s*100:.1f}%")

    # 2. Adaptive Baseline-Aware Threshold
    # Baseline estimated on normal traffic before attack
    normal_scores = [float(r["entropy_score"]) for r in rows if parse_ts(r["timestamp"]) < start_ts]
    if not normal_scores:
        normal_scores = [0.95, 0.96, 0.955, 0.962, 0.958] # typical baseline
    base_mean = np.mean(normal_scores)
    base_std = np.std(normal_scores) if np.std(normal_scores) > 0.005 else 0.015
    print(f"\nCalibrated Normal Baseline: Mean={base_mean:.4f}, Std={base_std:.4f}")

    # Threshold: deviation delta > 0.04 or score < baseline - 2.0*std
    adaptive_thresh = base_mean - 2.0 * base_std
    print(f"Adaptive Decision Threshold: {adaptive_thresh:.4f}")

    tp_a = fp_a = tn_a = fn_a = 0
    for r in filtered:
        ts = parse_ts(r["timestamp"])
        actual_pos = any(w.contains(ts, pad_sec=MONITOR_INTERVAL_DEFAULT) for w in windows)
        score = float(r.get("entropy_score", 1.0))
        pkt_ent = float(r.get("packet_entropy", 1.0))
        
        # Adaptive rule: score drops below adaptive threshold OR packet entropy drops < 0.85 with delta > 0.035
        pred_pos = (score < adaptive_thresh) or (pkt_ent < 0.85 and (base_mean - score) > 0.035)
        
        if pred_pos and actual_pos: tp_a += 1
        elif pred_pos and not actual_pos: fp_a += 1
        elif not pred_pos and not actual_pos: tn_a += 1
        else: fn_a += 1
        
    print(f"Adaptive Thresholding -> TP={tp_a}, FP={fp_a}, TN={tn_a}, FN={fn_a}")
    rec_a = tp_a / (tp_a + fn_a) if (tp_a + fn_a) > 0 else 0
    prec_a = tp_a / (tp_a + fp_a) if (tp_a + fp_a) > 0 else 0
    f1_a = 2 * prec_a * rec_a / (prec_a + rec_a) if (prec_a + rec_a) > 0 else 0
    acc_a = (tp_a + tn_a) / len(filtered)
    fpr_a = fp_a / (fp_a + tn_a) if (fp_a + tn_a) > 0 else 0
    print(f"  Accuracy={acc_a*100:.1f}%, Recall={rec_a*100:.1f}%, Precision={prec_a*100:.1f}%, F1={f1_a*100:.1f}%, FPR={fpr_a*100:.1f}%")

if __name__ == "__main__":
    main()

