import pandas as pd
import numpy as np
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.model_selection import GroupKFold, cross_val_score, StratifiedGroupKFold
from sklearn.metrics import roc_auc_score

df = pd.read_csv("data/authentic_insdn_leakage_free.csv")
FEATURE_NAMES = [
    "packet_rate_mean", "packet_rate_max", "byte_rate_mean", "byte_rate_max",
    "flow_count", "unique_src_count", "unique_dst_count", "src_entropy",
    "dst_entropy", "packet_entropy", "byte_entropy", "flow_entropy",
    "entropy_score", "flow_concentration"
]

# Filter to attack windows where source is metasploitable-2 or OVS
# (or across all windows)
# In Task 12: y_source = (df["capture_source"] == "metasploitable-2").astype(int).values
# But wait, df["capture_source"] has "Normal_data", "metasploitable-2", and "OVS"!
print("Capture source counts:")
print(df["capture_source"].value_counts())

# Let's inspect between metasploitable-2 and OVS:
sub = df[df["capture_source"].isin(["metasploitable-2", "OVS"])].copy().reset_index(drop=True)
X_sub = sub[FEATURE_NAMES].values
y_sub = (sub["capture_source"] == "metasploitable-2").astype(int).values
groups_sub = sub["session_group"].values

# Standard 5-fold (ungrouped, as in Task 12):
dt = DecisionTreeClassifier(max_depth=3, random_state=42)
lr = LogisticRegression(max_iter=1000, random_state=42)

cv_dt_ungrouped = cross_val_score(dt, X_sub, y_sub, cv=5, scoring="roc_auc")
cv_lr_ungrouped = cross_val_score(lr, X_sub, y_sub, cv=5, scoring="roc_auc")
print(f"Ungrouped 5-Fold AUC (metasploitable-2 vs OVS):")
print(f"  Decision Tree:       {np.mean(cv_dt_ungrouped):.4f} +/- {np.std(cv_dt_ungrouped):.4f}")
print(f"  Logistic Regression: {np.mean(cv_lr_ungrouped):.4f} +/- {np.std(cv_lr_ungrouped):.4f}")

# Grouped 5-fold by session_group:
sgkf = StratifiedGroupKFold(n_splits=5)
# Check if StratifiedGroupKFold works or GroupKFold
try:
    cv_dt_grouped = cross_val_score(dt, X_sub, y_sub, cv=sgkf, groups=groups_sub, scoring="roc_auc")
    cv_lr_grouped = cross_val_score(lr, X_sub, y_sub, cv=sgkf, groups=groups_sub, scoring="roc_auc")
    print(f"\nSession-Grouped 5-Fold AUC (metasploitable-2 vs OVS):")
    print(f"  Decision Tree:       {np.mean(cv_dt_grouped):.4f} +/- {np.std(cv_dt_grouped):.4f}")
    print(f"  Logistic Regression: {np.mean(cv_lr_grouped):.4f} +/- {np.std(cv_lr_grouped):.4f}")
except Exception as e:
    print("StratifiedGroupKFold error:", e)

# Also check across ALL windows (including Normal_data, if binary metasploitable-2 vs rest)
X_all = df[FEATURE_NAMES].values
y_all = (df["capture_source"] == "metasploitable-2").astype(int).values
groups_all = df["session_group"].values
cv_dt_all_ungrouped = cross_val_score(dt, X_all, y_all, cv=5, scoring="roc_auc")
cv_dt_all_grouped = cross_val_score(dt, X_all, y_all, cv=sgkf, groups=groups_all, scoring="roc_auc")
print(f"\nAll Windows (metasploitable-2 vs rest):")
print(f"  Ungrouped DT AUC: {np.mean(cv_dt_all_ungrouped):.4f}")
print(f"  Grouped DT AUC:   {np.mean(cv_dt_all_grouped):.4f}")

