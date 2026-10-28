#!/usr/bin/env python3
"""
IntelliShield SDN — Task 18: Mininet Dataset Builder
Aggregates raw packet telemetry into fixed observation time windows, computes
the standard 14 InSDN-compatible features, and assigns ground-truth labels purely
from experiment schedule timestamps.
"""

import os
import sys
import json
import math
import hashlib
import numpy as np
import pandas as pd
from collections import Counter
from typing import Dict, List, Any, Tuple

_FILE_DIR = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_FILE_DIR) if os.path.basename(_FILE_DIR) == "scripts" else _FILE_DIR
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

DATA_DIR = os.path.join(_ROOT, "data", "task18_mininet")
RAW_DIR = os.path.join(DATA_DIR, "raw")
RAW_PACKETS_CSV = os.path.join(RAW_DIR, "raw_packet_stream.csv")
SCHEDULE_JSON = os.path.join(RAW_DIR, "experiment_schedule.json")

OUT_DATASET_CSV = os.path.join(DATA_DIR, "mininet_unseen_capture.csv")
OUT_MANIFEST_JSON = os.path.join(DATA_DIR, "task18_dataset_manifest.json")


def compute_sha256(filepath: str) -> str:
    if not os.path.exists(filepath):
        return "FILE_NOT_FOUND"
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


def calc_shannon_entropy(values: List[Any]) -> float:
    """Computes normalized Shannon entropy in [0, 1]."""
    if not values:
        return 0.0
    n = len(values)
    counts = Counter(values)
    k = len(counts)
    if k <= 1:
        return 0.0
    probs = [c / n for c in counts.values()]
    h = -sum(p * math.log2(p) for p in probs)
    max_h = math.log2(k)
    return round(float(h / max_h), 6) if max_h > 0 else 0.0


def build_dataset(window_size_sec: float = 2.0):
    print("=" * 80)
    print("TASK 18: BUILDING MININET WINDOWED DATASET")
    print("=" * 80)

    if not os.path.exists(RAW_PACKETS_CSV) or not os.path.exists(SCHEDULE_JSON):
        raise FileNotFoundError("Raw packet stream or experiment schedule missing!")

    print(f"Reading raw packets: {RAW_PACKETS_CSV}...")
    df_pkts = pd.read_csv(RAW_PACKETS_CSV)
    print(f"Total raw packets loaded: {len(df_pkts)}")

    with open(SCHEDULE_JSON, "r") as f:
        schedule = json.load(f)

    sessions = schedule["sessions"]
    print(f"Total sessions in experiment schedule: {len(sessions)}")

    window_records = []
    window_counter = 0

    for sess in sessions:
        sid = sess["session_id"]
        s_start = sess["session_start"]
        s_end = sess["session_end"]
        attacks = sess["active_attacks"]

        sess_pkts = df_pkts[(df_pkts["timestamp"] >= s_start) & (df_pkts["timestamp"] <= s_end)].copy()
        print(f"Processing {sid}: duration {s_end - s_start:.2f}s, packets: {len(sess_pkts)}")

        # Step through windows
        cur_start = s_start
        while cur_start + window_size_sec <= s_end:
            cur_end = cur_start + window_size_sec
            w_pkts = sess_pkts[(sess_pkts["timestamp"] >= cur_start) & (sess_pkts["timestamp"] < cur_end)]

            # Determine ground truth label purely from timestamps
            is_attack = False
            active_atk_type = "NORMAL"

            for atk in attacks:
                a_st = atk["start_time"]
                a_en = atk["end_time"]
                # Check interval overlap: max(start) < min(end)
                if max(cur_start, a_st) < min(cur_end, a_en):
                    is_attack = True
                    active_atk_type = atk["attack_type"]
                    break

            gt_label = 1 if is_attack else 0
            n_pkts = len(w_pkts)
            total_bytes = w_pkts["packet_length"].sum() if n_pkts > 0 else 0

            # Feature calculation
            pkt_rate_mean = round(float(n_pkts / window_size_sec), 4)
            byte_rate_mean = round(float(total_bytes / window_size_sec), 4)

            if n_pkts > 0:
                # Group by 5-tuple
                flows = list(zip(
                    w_pkts["src_ip"].fillna(""),
                    w_pkts["dst_ip"].fillna(""),
                    w_pkts["src_port"].fillna(0),
                    w_pkts["dst_port"].fillna(0),
                    w_pkts["protocol"].fillna("")
                ))
                flow_counts = Counter(flows)
                flow_count = len(flow_counts)
                max_flow_pkts = max(flow_counts.values()) if flow_counts else 0
                pkt_rate_max = round(float(max_flow_pkts / window_size_sec), 4)

                # Flow bytes
                w_pkts_flow = w_pkts.copy()
                w_pkts_flow["flow_tuple"] = flows
                flow_bytes = w_pkts_flow.groupby("flow_tuple")["packet_length"].sum().to_dict()
                max_flow_bytes = max(flow_bytes.values()) if flow_bytes else 0
                byte_rate_max = round(float(max_flow_bytes / window_size_sec), 4)

                flow_conc = round(float(max_flow_pkts / n_pkts), 6)

                u_src = int(w_pkts["src_ip"].nunique())
                u_dst = int(w_pkts["dst_ip"].nunique())

                # Entropies
                h_src = calc_shannon_entropy(w_pkts["src_ip"].dropna().tolist())
                h_dst = calc_shannon_entropy(w_pkts["dst_ip"].dropna().tolist())
                h_port = calc_shannon_entropy(w_pkts["dst_port"].dropna().tolist())
                h_byte = calc_shannon_entropy(list(flow_bytes.values()))
                h_flow = calc_shannon_entropy(list(flow_counts.values()))
                ent_score = round(float(0.4 * h_dst + 0.4 * h_port + 0.2 * h_src), 6)
            else:
                flow_count = 0
                pkt_rate_max = 0.0
                byte_rate_max = 0.0
                flow_conc = 0.0
                u_src = 0
                u_dst = 0
                h_src = 0.0
                h_dst = 0.0
                h_port = 0.0
                h_byte = 0.0
                h_flow = 0.0
                ent_score = 0.0

            rec = {
                "raw_window_id": window_counter,
                "session_group": sid,
                "capture_source": "Mininet",
                "ground_truth": gt_label,
                "attack_type": active_atk_type,
                "window_start": cur_start,
                "window_end": cur_end,
                "packet_rate_mean": pkt_rate_mean,
                "packet_rate_max": pkt_rate_max,
                "byte_rate_mean": byte_rate_mean,
                "byte_rate_max": byte_rate_max,
                "flow_count": flow_count,
                "unique_src_count": u_src,
                "unique_dst_count": u_dst,
                "src_entropy": h_src,
                "dst_entropy": h_dst,
                "packet_entropy": h_port,
                "byte_entropy": h_byte,
                "flow_entropy": h_flow,
                "entropy_score": ent_score,
                "flow_concentration": flow_conc,
                "duration_mean": window_size_sec,
            }
            window_records.append(rec)
            window_counter += 1
            cur_start += window_size_sec

    df_dataset = pd.DataFrame(window_records)
    df_dataset.to_csv(OUT_DATASET_CSV, index=False)
    print(f"\nSaved windowed Mininet dataset: {OUT_DATASET_CSV} ({len(df_dataset)} rows)")

    # Class balance summary
    attack_counts = df_dataset["attack_type"].value_counts().to_dict()
    label_counts = df_dataset["ground_truth"].value_counts().to_dict()
    print("Class Balance:")
    print("  Ground Truth Labels:", label_counts)
    print("  Attack Types:       ", attack_counts)

    manifest = {
        "dataset_name": "Mininet Unseen Capture (Task 18)",
        "output_path": "data/task18_mininet/mininet_unseen_capture.csv",
        "sha256": compute_sha256(OUT_DATASET_CSV),
        "total_windows": len(df_dataset),
        "window_size_sec": window_size_sec,
        "total_sessions": len(sessions),
        "label_distribution": {str(k): int(v) for k, v in label_counts.items()},
        "attack_type_distribution": {str(k): int(v) for k, v in attack_counts.items()},
        "features": [
            "packet_rate_mean", "packet_rate_max", "byte_rate_mean", "byte_rate_max",
            "flow_count", "unique_src_count", "unique_dst_count", "src_entropy",
            "dst_entropy", "packet_entropy", "byte_entropy", "flow_entropy",
            "entropy_score", "flow_concentration"
        ],
    }

    with open(OUT_MANIFEST_JSON, "w") as f:
        json.dump(manifest, f, indent=2)
    print(f"Saved dataset manifest: {OUT_MANIFEST_JSON}")


if __name__ == "__main__":
    build_dataset()

