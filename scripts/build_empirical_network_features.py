#!/usr/bin/env python3
"""
IntelliShield SDN — Empirical Label-Independent Network Feature Builder
Computes all 15 OpenFlow features exclusively from raw network fields:
- Src IP, Dst IP, Dst Port, Protocol
- Flow Pkts/s, Flow Byts/s, Flow Duration, Fwd Pkt Len Max, Tot Fwd Pkts

Core Principles:
1. Strict Label Independence: Operates entirely without access to target labels.
2. Invariance: Removing or shuffling labels yields 100% identical feature vectors.
3. Empirical Grounding: Entropies, host counts, and concentration indices are computed
   directly from observed distributions in chronological/tumbling flow windows.
"""

import math
import numpy as np
import pandas as pd
from typing import List, Dict, Optional, Tuple

FEATURE_NAMES = [
    "packet_rate_mean",
    "packet_rate_max",
    "byte_rate_mean",
    "byte_rate_max",
    "flow_count",
    "duration_mean",
    "unique_src_count",
    "unique_dst_count",
    "src_entropy",
    "dst_entropy",
    "packet_entropy",
    "byte_entropy",
    "flow_entropy",
    "entropy_score",
    "flow_concentration",
]

def shannon_entropy_from_values(values: np.ndarray, max_categories: int = 32) -> float:
    """
    Computes normalized Shannon entropy H(X) / log2(min(N, max_categories))
    from a 1D array of observed categorical values.
    Returns 0.0 if empty or uniform single-value.
    """
    n = len(values)
    if n <= 1:
        return 0.0
    
    # Calculate frequency distribution
    _, counts = np.unique(values, return_counts=True)
    probs = counts / n
    h_raw = -np.sum(probs * np.log2(probs + 1e-12))
    
    # Normalization factor
    denom = math.log2(min(n, max_categories))
    if denom <= 0:
        return 0.0
    return float(np.clip(h_raw / denom, 0.0, 1.0))

def herfindahl_concentration(values: np.ndarray) -> float:
    """
    Computes Herfindahl-Hirschman Index (HHI) = sum(p_i^2) of destination distribution.
    Ranges from 1/N (uniform dispersion) to 1.0 (pure concentration on single host).
    """
    n = len(values)
    if n == 0:
        return 0.0
    _, counts = np.unique(values, return_counts=True)
    probs = counts / n
    return float(np.clip(np.sum(probs ** 2), 0.0, 1.0))

def extract_window_features(
    src_ips: np.ndarray,
    dst_ips: np.ndarray,
    dst_ports: np.ndarray,
    protocols: np.ndarray,
    pkt_rates: np.ndarray,
    byte_rates: np.ndarray,
    durations: np.ndarray,
    fwd_len_max: Optional[np.ndarray] = None
) -> Dict[str, float]:
    """
    Extracts 15 empirical network features from a batch/window of concurrent flows.
    Strictly NO label parameter exists in this function.
    """
    n = len(src_ips)
    if n == 0:
        return {feat: 0.0 for feat in FEATURE_NAMES}

    # 1-6. Volumetric & rate metrics
    pr_mean = float(np.mean(pkt_rates))
    pr_max = float(np.max(pkt_rates))
    br_mean = float(np.mean(byte_rates))
    br_max = float(np.max(byte_rates))
    flow_cnt = float(n)
    dur_mean = float(np.mean(durations))

    # 7-8. Unique host counts
    u_src = float(len(np.unique(src_ips)))
    u_dst = float(len(np.unique(dst_ips)))

    # 9. Source IP entropy
    src_ent = shannon_entropy_from_values(src_ips, max_categories=32)

    # 10. Destination IP entropy
    dst_ent = shannon_entropy_from_values(dst_ips, max_categories=32)

    # 11. Destination Port entropy (anomalous dispersion in PROBE/port scan)
    port_ent = shannon_entropy_from_values(dst_ports, max_categories=32)

    # 12. Packet rate distribution entropy (load uniformity across flows)
    # Bin continuous rates into 8 quantiles
    if len(np.unique(pkt_rates)) > 1:
        try:
            binned_pr = pd.qcut(pkt_rates, q=min(8, len(np.unique(pkt_rates))), labels=False, duplicates='drop')
            byte_ent = shannon_entropy_from_values(binned_pr, max_categories=8)
        except Exception:
            byte_ent = 0.5
    else:
        byte_ent = 0.0

    # 13. Protocol distribution entropy
    flow_ent = shannon_entropy_from_values(protocols, max_categories=8)

    # 14. Composite entropy score
    ent_score = (
        0.25 * src_ent +
        0.25 * dst_ent +
        0.25 * port_ent +
        0.15 * byte_ent +
        0.10 * flow_ent
    )

    # 15. Flow concentration (destination HHI)
    flow_conc = herfindahl_concentration(dst_ips)

    return {
        "packet_rate_mean": round(pr_mean, 4),
        "packet_rate_max": round(pr_max, 4),
        "byte_rate_mean": round(br_mean, 4),
        "byte_rate_max": round(br_max, 4),
        "flow_count": round(flow_cnt, 4),
        "duration_mean": round(dur_mean, 4),
        "unique_src_count": round(u_src, 4),
        "unique_dst_count": round(u_dst, 4),
        "src_entropy": round(src_ent, 6),
        "dst_entropy": round(dst_ent, 6),
        "packet_entropy": round(port_ent, 6), # mapped to port dispersion
        "byte_entropy": round(byte_ent, 6),
        "flow_entropy": round(flow_ent, 6),
        "entropy_score": round(ent_score, 6),
        "flow_concentration": round(flow_conc, 6),
    }

def process_dataframe_into_empirical_windows(
    df: pd.DataFrame,
    window_size: int = 50,
    has_labels: bool = True
) -> pd.DataFrame:
    """
    Transforms raw network flow records into empirical monitoring windows of size W.
    Guarantees that input features are computed completely independently of any labels.
    """
    # Clean and validate input columns
    cols = df.columns
    src_col = [c for c in cols if "src ip" in c.lower()][0]
    dst_col = [c for c in cols if "dst ip" in c.lower()][0]
    port_col = [c for c in cols if "dst port" in c.lower() or "destination port" in c.lower()][0]
    proto_col = [c for c in cols if "protocol" in c.lower()][0]
    pkt_col = [c for c in cols if "pkts/s" in c.lower()][0]
    byte_col = [c for c in cols if "byts/s" in c.lower()][0]
    dur_col = [c for c in cols if "flow duration" in c.lower()][0]

    src_arr = df[src_col].astype(str).values
    dst_arr = df[dst_col].astype(str).values
    port_arr = pd.to_numeric(df[port_col], errors="coerce").fillna(0).astype(int).values
    proto_arr = pd.to_numeric(df[proto_col], errors="coerce").fillna(0).astype(int).values
    pkt_arr = pd.to_numeric(df[pkt_col], errors="coerce").fillna(0.0).values
    byte_arr = pd.to_numeric(df[byte_col], errors="coerce").fillna(0.0).values
    dur_arr = pd.to_numeric(df[dur_col], errors="coerce").fillna(0.0).values / 1e6

    ts_cols = [c for c in cols if "timestamp" in c.lower()]
    ts_arr = df[ts_cols[0]].astype(str).values if ts_cols else None

    lbl_col = [c for c in cols if "label" in c.lower()] if has_labels else []
    labels_arr = df[lbl_col[0]].values if lbl_col else None

    n_total = len(df)
    window_records = []

    for start_idx in range(0, n_total, window_size):
        end_idx = min(start_idx + window_size, n_total)
        w_len = end_idx - start_idx
        if w_len < 5:
            continue

        w_feats = extract_window_features(
            src_ips=src_arr[start_idx:end_idx],
            dst_ips=dst_arr[start_idx:end_idx],
            dst_ports=port_arr[start_idx:end_idx],
            protocols=proto_arr[start_idx:end_idx],
            pkt_rates=pkt_arr[start_idx:end_idx],
            byte_rates=byte_arr[start_idx:end_idx],
            durations=dur_arr[start_idx:end_idx]
        )

        # Raw capture session identifier (mode timestamp of the window)
        if ts_arr is not None:
            w_feats["session_id"] = str(pd.Series(ts_arr[start_idx:end_idx]).mode().iloc[0]).strip()
        else:
            w_feats["session_id"] = f"win_{start_idx // window_size}"

        # Assign post-hoc evaluation target if labels exist
        if labels_arr is not None:
            w_lbls = labels_arr[start_idx:end_idx]
            mode_lbl = str(pd.Series(w_lbls).mode().iloc[0])
            s_clean = mode_lbl.strip().upper()
            if "NORMAL" in s_clean or "BENIGN" in s_clean:
                bin_lbl = 0
                att_family = "NORMAL"
            elif "DDOS" in s_clean:
                bin_lbl = 1
                att_family = "DDOS"
            elif "DOS" in s_clean:
                bin_lbl = 1
                att_family = "DOS"
            elif "PROBE" in s_clean or "SCAN" in s_clean:
                bin_lbl = 1
                att_family = "PROBE"
            elif "BFA" in s_clean or "BRUTE" in s_clean:
                bin_lbl = 1
                att_family = "BRUTE_FORCE"
            elif "BOTNET" in s_clean:
                bin_lbl = 1
                att_family = "BOTNET"
            else:
                bin_lbl = 1
                att_family = "OTHER_ATTACK"

            w_feats["label"] = bin_lbl
            w_feats["attack_type"] = att_family
            w_feats["raw_label"] = mode_lbl

        window_records.append(w_feats)

    return pd.DataFrame(window_records)

if __name__ == "__main__":
    print(f"[EmpiricalNetworkFeatures] Schema loaded with {len(FEATURE_NAMES)} features.")

