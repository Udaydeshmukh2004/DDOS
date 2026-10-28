"""
Inspect all 29 cycles: flow stats, entropy scores, and window labels
"""
import csv, os, sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
from evaluation.experiment_windows import load_experiment_windows, parse_ts, MONITOR_INTERVAL_DEFAULT

def main():
    windows = load_experiment_windows(os.path.join(_ROOT, "logs"))
    start_ts = parse_ts("2026-10-22 19:46:00")
    stop_ts = parse_ts("2026-10-22 19:48:40")

    # Load flow stats
    flow_map = {}
    with open(os.path.join(_ROOT, "logs", "flow_stats.csv")) as f:
        for r in csv.DictReader(f):
            ts = parse_ts(r["timestamp"])
            if ts and start_ts <= ts <= stop_ts:
                # aggregate packet rate
                pr = float(r.get("packet_rate", 0))
                flow_map[r["timestamp"]] = flow_map.get(r["timestamp"], 0.0) + pr

    # Load entropy rows
    with open(os.path.join(_ROOT, "logs", "entropy_logs.csv")) as f:
        rows = [r for r in csv.DictReader(f) if start_ts <= parse_ts(r["timestamp"]) <= stop_ts]

    print(f"{'Timestamp':<20} {'Act':<5} {'Score':<8} {'SrcEnt':<8} {'DstEnt':<8} {'PktEnt':<8} {'AggRate':<10} {'Matching Window'}")
    print("-" * 90)
    for r in rows:
        ts = parse_ts(r["timestamp"])
        match = [w.scenario for w in windows if w.contains(ts, pad_sec=MONITOR_INTERVAL_DEFAULT)]
        act = "ATTK" if match else "NORM"
        rate = flow_map.get(r["timestamp"], 0.0)
        print(f"{r['timestamp']:<20} {act:<5} {r['entropy_score']:<8} {r['src_entropy']:<8} {r['dst_entropy']:<8} {r['packet_entropy']:<8} {rate:<10.1f} {match}")

if __name__ == "__main__":
    main()

