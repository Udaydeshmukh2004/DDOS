#!/usr/bin/env python3
import os
import sys
import pickle
import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
from ml_models.feature_builder import FEATURE_NAMES

df_all = pd.read_csv(os.path.join(_ROOT, "logs", "ml_features.csv"))
start_ts, end_ts = "2026-10-22 19:46:02", "2026-10-22 19:48:34"
df_live = df_all[(df_all["timestamp"] >= start_ts) & (df_all["timestamp"] <= end_ts)].copy()

actual_pos = [0 if ts in ("2026-10-22 19:46:43", "2026-10-22 19:47:18", "2026-10-22 19:47:23") else 1 for ts in df_live["timestamp"]]
actual_pos = np.array(actual_pos)

with open(os.path.join(_ROOT, "logs", "models", "random_forest.pkl"), "rb") as f:
    rf = pickle.load(f)
with open(os.path.join(_ROOT, "logs", "models", "scaler.pkl"), "rb") as f:
    scaler = pickle.load(f)

X_live = df_live[FEATURE_NAMES].values
X_scaled = scaler.transform(X_live)
rf_preds = rf.predict(X_scaled)

pkt_ent = X_live[:, FEATURE_NAMES.index("packet_entropy")]
ent_score = X_live[:, FEATURE_NAMES.index("entropy_score")]

for pkt_th, ent_th in [(0.72, 0.91), (0.75, 0.92), (0.75, 0.93)]:
    hybrid_preds = np.zeros(len(actual_pos), dtype=int)
    for i in range(len(actual_pos)):
        if rf_preds[i] == 1 or (pkt_ent[i] <= pkt_th and ent_score[i] <= ent_th):
            hybrid_preds[i] = 1

    tn, fp, fn, tp = confusion_matrix(actual_pos, hybrid_preds, labels=[0, 1]).ravel()
    acc = (tp + tn) / 24 * 100.0
    rec = tp / 21 * 100.0
    prec = tp / (tp + fp) * 100.0 if (tp + fp) > 0 else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0
    print(f"pkt_th={pkt_th:.2f}, ent_th={ent_th:.2f} -> TP={tp:2d}, FP={fp:2d}, TN={tn:2d}, FN={fn:2d} | Acc={acc:.2f}% | Rec={rec:.2f}% | Prec={prec:.2f}% | F1={f1:.2f}%")
