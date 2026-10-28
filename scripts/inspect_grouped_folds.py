import pandas as pd
import numpy as np
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_auc_score

bench_df = pd.read_csv("data/authentic_insdn_leakage_free.csv")
sub = bench_df[bench_df["capture_source"].isin(["metasploitable-2", "OVS"])].copy().reset_index(drop=True)

FEATURE_NAMES = [
    "packet_rate_mean", "packet_rate_max", "byte_rate_mean", "byte_rate_max",
    "flow_count", "unique_src_count", "unique_dst_count", "src_entropy",
    "dst_entropy", "packet_entropy", "byte_entropy", "flow_entropy",
    "entropy_score", "flow_concentration"
]
eval_features = [f for f in FEATURE_NAMES if f in bench_df.columns]

X_sub = sub[eval_features].values
y_sub = (sub["capture_source"] == "metasploitable-2").astype(int).values
groups_sub = sub["session_group"].values

print("Total samples in sub:", len(sub))
print("Total unique sessions in sub:", len(np.unique(groups_sub)))
print("Source distribution in sub:", dict(sub["capture_source"].value_counts()))

# Session sizes
session_sizes = sub.groupby("session_group").size()
print(f"Session sizes: min={session_sizes.min()}, max={session_sizes.max()}, median={session_sizes.median()}")
print("Top 10 largest sessions:")
print(session_sizes.sort_values(ascending=False).head(10))

sgkf = StratifiedGroupKFold(n_splits=5)
fold_idx = 1
for tr_idx, te_idx in sgkf.split(X_sub, y_sub, groups=groups_sub):
    tr_groups = set(groups_sub[tr_idx])
    te_groups = set(groups_sub[te_idx])
    overlap = tr_groups.intersection(te_groups)
    
    y_tr_f = y_sub[tr_idx]
    y_te_f = y_sub[te_idx]
    
    print(f"\n--- FOLD {fold_idx} ---")
    print(f"Train sessions: {len(tr_groups)}, Test sessions: {len(te_groups)}, Overlap: {len(overlap)}")
    print(f"Train classes: m2={np.sum(y_tr_f==1)}, ovs={np.sum(y_tr_f==0)}")
    print(f"Test classes:  m2={np.sum(y_te_f==1)}, ovs={np.sum(y_te_f==0)}")
    print(f"Test sessions list: {te_groups}")
    
    dt = DecisionTreeClassifier(max_depth=3, random_state=42)
    dt.fit(X_sub[tr_idx], y_tr_f)
    p_dt = dt.predict_proba(X_sub[te_idx])[:, 1]
    auc_dt = roc_auc_score(y_te_f, p_dt)
    
    scaler = StandardScaler()
    X_tr_s = scaler.fit_transform(X_sub[tr_idx])
    X_te_s = scaler.transform(X_sub[te_idx])
    lr = LogisticRegression(max_iter=1000, random_state=42)
    lr.fit(X_tr_s, y_tr_f)
    p_lr = lr.predict_proba(X_te_s)[:, 1]
    auc_lr = roc_auc_score(y_te_f, p_lr)
    
    print(f"DT AUC: {auc_dt:.4f}, LR AUC: {auc_lr:.4f}")
    print(f"LR predictions on test: min={p_lr.min():.4f}, max={p_lr.max():.4f}, mean={p_lr.mean():.4f}")
    print(f"LR coefs: {dict(zip(eval_features, lr.coef_[0]))}")
    fold_idx += 1

