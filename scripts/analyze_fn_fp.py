"""
Analyze False Negatives in ml_predictions.csv
"""
import sys, os, csv

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

from evaluation.experiment_windows import load_experiment_windows, parse_ts, MONITOR_INTERVAL_DEFAULT
from evaluation.ieee_metrics import POSITIVE_PREDICTION

def main():
    windows = load_experiment_windows("logs")
    with open("logs/ml_predictions.csv") as f:
        rows = list(csv.DictReader(f))

    print(f"Total rows: {len(rows)}")
    for i, r in enumerate(rows, 1):
        ts = parse_ts(r["timestamp"])
        actual_pos = any(w.contains(ts, pad_sec=MONITOR_INTERVAL_DEFAULT) for w in windows)
        pred_pos = r["status"].upper() in POSITIVE_PREDICTION
        
        # Matching window
        matching_windows = [w.scenario for w in windows if w.contains(ts, pad_sec=MONITOR_INTERVAL_DEFAULT)]
        
        if actual_pos and not pred_pos:
            print(f"\n[FALSE NEGATIVE] Row {i:02d} @ {ts} | Matching Windows: {matching_windows}")
            print(f"  status={r['status']}, dt_label={r['dt_label']}, dt_conf={r['dt_confidence']}, hint={r['attack_type_hint']}")
            print(f"  pkt_rate_mean={r['packet_rate_mean']}, flow_count={r['flow_count']}, src_ent={r['src_entropy']}, dst_ent={r['dst_entropy']}, score={r['entropy_score']}")
        elif not actual_pos and pred_pos:
            print(f"\n[FALSE POSITIVE] Row {i:02d} @ {ts} | No Matching Windows")
            print(f"  status={r['status']}, dt_label={r['dt_label']}, dt_conf={r['dt_confidence']}, hint={r['attack_type_hint']}")
            print(f"  pkt_rate_mean={r['packet_rate_mean']}, flow_count={r['flow_count']}, src_ent={r['src_entropy']}, dst_ent={r['dst_entropy']}, score={r['entropy_score']}")

if __name__ == "__main__":
    main()

