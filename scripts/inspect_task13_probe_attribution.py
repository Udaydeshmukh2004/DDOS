import pandas as pd
import numpy as np

df = pd.read_csv("results/task11_non_rf_probe_attribution.csv")
s42 = df[df["seed"] == 42].copy()

dt = s42["pred_dt"].values
ent = s42["pred_ent_val"].values
src = s42["capture_source"].values
r_id = s42["raw_window_id"].values
sess = s42["session_group"].values
ports = s42["port_entropy"].values
p_dt = s42["dt_prob"].values

print("Total windows in seed 42:", len(s42))

dt_only = (dt == 1) & (ent == 0)
ent_only = (dt == 0) & (ent == 1)
both = (dt == 1) & (ent == 1)
neither = (dt == 0) & (ent == 0)

print(f"Both DT & Entropy: {np.sum(both)}")
print(f"DT Only: {np.sum(dt_only)}")
print(f"Entropy Only: {np.sum(ent_only)}")
print(f"Neither: {np.sum(neither)}")

print("\nBreakdown of DT-only windows by source:")
print(pd.Series(src[dt_only]).value_counts())

print("\nDetails of DT-only windows:")
dt_only_df = s42[dt_only][["raw_window_id", "capture_source", "session_group", "port_entropy", "dt_prob", "pred_dt", "pred_ent_val", "reason_hyb_dt"]]
print(dt_only_df.to_string())

print("\nBreakdown of Entropy-only windows by source:")
print(pd.Series(src[ent_only]).value_counts())

print("\nBreakdown of Both-triggered windows by source:")
print(pd.Series(src[both]).value_counts())

