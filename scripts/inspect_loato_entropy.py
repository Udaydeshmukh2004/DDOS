import numpy as np
import pandas as pd
from sklearn.model_selection import GroupShuffleSplit

bench_df = pd.read_csv("data/authentic_insdn_leakage_free.csv")
bench_df["raw_window_id"] = np.arange(len(bench_df))

FEATURE_NAMES = [
    "packet_rate_mean", "packet_rate_max", "byte_rate_mean", "byte_rate_max",
    "flow_count", "unique_src_count", "unique_dst_count", "src_entropy",
    "dst_entropy", "packet_entropy", "byte_entropy", "flow_entropy",
    "entropy_score", "flow_concentration"
]
eval_features = [f for f in FEATURE_NAMES if f in bench_df.columns]
port_ent_idx = eval_features.index("packet_entropy")

print("eval_features[port_ent_idx]:", eval_features[port_ent_idx])

# Check PROBE
held_out = "PROBE"
seed = 42
known_df = bench_df[bench_df["attack_type"] != held_out].copy()
unseen_df = bench_df[bench_df["attack_type"] == held_out].copy()
normal_pool = bench_df[bench_df["attack_type"] == "NORMAL"].copy()

gss_test = GroupShuffleSplit(n_splits=1, test_size=0.20, random_state=seed)
n_tr_val_idx, n_test_idx = next(gss_test.split(normal_pool, groups=normal_pool["session_group"]))
norm_test = normal_pool.iloc[n_test_idx]

n_unseen = len(unseen_df)
n_test_norm = min(len(norm_test), n_unseen * 2)
norm_test_sampled = norm_test.sample(n=n_test_norm, random_state=seed)
test_df = pd.concat([norm_test_sampled, unseen_df], ignore_index=True)

X_te = test_df[eval_features].values
y_te = test_df["label"].values

te_ports = X_te[:, port_ent_idx]
print(f"Total test windows: {len(test_df)}")
print(f"Normal in test: {len(norm_test_sampled)}, Attack in test: {len(unseen_df)}")

# Check probe part of test_df
probe_mask = (test_df["attack_type"] == "PROBE").values
probe_ports = te_ports[probe_mask]

ge_085_probe = (probe_ports >= 0.85).sum()
print(f"probe_ports >= 0.85: {ge_085_probe} / {len(probe_ports)}")

# Check all test windows
pred_apr = (te_ports >= 0.85).astype(int)
tp = ((pred_apr == 1) & (y_te == 1)).sum()
fp = ((pred_apr == 1) & (y_te == 0)).sum()
fn = ((pred_apr == 0) & (y_te == 1)).sum()
tn = ((pred_apr == 0) & (y_te == 0)).sum()
print(f"TP={tp}, FP={fp}, TN={tn}, FN={fn}")
print(f"Recall: {tp}/{tp+fn} = {tp/(tp+fn):.4f}")

