import pandas as pd
import numpy as np

# Load benchmark
bench_df = pd.read_csv("data/authentic_insdn_leakage_free.csv")
bench_df["raw_window_id"] = np.arange(len(bench_df))
probe_df = bench_df[bench_df["attack_type"] == "PROBE"].copy().reset_index(drop=True)
probe_df["probe_idx"] = np.arange(len(probe_df))

print(f"Total PROBE windows in benchmark: {len(probe_df)}")
print("Probe by source:")
print(probe_df["capture_source"].value_counts())
print("\nProbe by session_group:")
print(probe_df["session_group"].value_counts().head(10))

# Load saved predictions
preds_df = pd.read_csv("results/task6_per_observation_predictions.csv")
print(f"\nTotal rows in task6 predictions: {len(preds_df)}")

# For seed 42:
for seed in [42, 101, 777, 999, 2026]:
    sub = preds_df[preds_df["seed"] == seed].reset_index(drop=True)
    # The attacks are the rows with y_true == 1
    att_sub = sub[sub["y_true"] == 1].reset_index(drop=True)
    assert len(att_sub) == 500, f"Expected 500 attacks, got {len(att_sub)}"
    
    # Merge with probe_df
    merged = pd.concat([probe_df, att_sub[["pred_rf", "pred_ent", "pred_hyb_std", "pred_hyb_ovr_apr", "port_entropy", "rf_prob"]]], axis=1)
    
    # Check decision reason for pred_hyb_ovr_apr:
    # 1. Triggered by port_entropy >= 0.85 (structural override)
    # 2. Triggered by rf_prob >= 0.75 (supervised high confidence)
    # 3. Triggered by uncertain zone (0.25 < rf_prob < 0.75 and (port >= th_p or conc >= th_c))
    reason_ovr = (merged["port_entropy"] >= 0.85)
    reason_rf_high = (~reason_ovr) & (merged["rf_prob"] >= 0.75)
    reason_gating = (~reason_ovr) & (~reason_rf_high) & (merged["pred_hyb_ovr_apr"] == 1)
    missed = (merged["pred_hyb_ovr_apr"] == 0)
    
    print(f"\n--- SEED {seed} ATTRIBUTION ---")
    print(f"  Total Probe: {len(merged)}")
    print(f"  RF positive (pred_rf == 1)         : {merged['pred_rf'].sum()} ({merged['pred_rf'].mean()*100:.2f}%)")
    print(f"  Entropy positive (pred_ent == 1)   : {merged['pred_ent'].sum()} ({merged['pred_ent'].mean()*100:.2f}%)")
    print(f"  Hybrid Override (pred_hyb_ovr == 1): {merged['pred_hyb_ovr_apr'].sum()} ({merged['pred_hyb_ovr_apr'].mean()*100:.2f}%)")
    print(f"    - Due to Port Entropy >= 0.85    : {reason_ovr.sum()}")
    print(f"    - Due to RF prob >= 0.75         : {reason_rf_high.sum()}")
    print(f"    - Due to Uncertainty Gating      : {reason_gating.sum()}")
    print(f"    - Missed                         : {missed.sum()}")
    
    # Breakdown by capture source:
    for src in ["metasploitable-2", "OVS"]:
        src_df = merged[merged["capture_source"] == src]
        print(f"    Source [{src:<16}] (N={len(src_df)}):")
        print(f"      RF Recall       : {src_df['pred_rf'].mean()*100:.2f}% ({src_df['pred_rf'].sum()}/{len(src_df)})")
        print(f"      Entropy Recall  : {src_df['pred_ent'].mean()*100:.2f}% ({src_df['pred_ent'].sum()}/{len(src_df)})")
        print(f"      Hybrid Ov Recall: {src_df['pred_hyb_ovr_apr'].mean()*100:.2f}% ({src_df['pred_hyb_ovr_apr'].sum()}/{len(src_df)})")
        print(f"      Mean Port Entropy: {src_df['port_entropy'].mean():.4f}")
        print(f"      Mean RF Prob     : {src_df['rf_prob'].mean():.4f}")

