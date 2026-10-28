import pandas as pd

df = pd.read_csv("results/task10_probe_prediction_attribution.csv")
print("Seed breakdown for metasploitable-2:")
for s in [42, 101, 777, 999, 2026]:
    sub = df[(df["seed"] == s) & (df["capture_source"] == "metasploitable-2")]
    print(f"Seed {s}: rf={sub['pred_rf'].sum()}, ent={sub['pred_ent'].sum()}, hyb={sub['pred_hyb_ovr'].sum()}")

print("\nSeed breakdown for OVS:")
for s in [42, 101, 777, 999, 2026]:
    sub = df[(df["seed"] == s) & (df["capture_source"] == "OVS")]
    print(f"Seed {s}: rf={sub['pred_rf'].sum()}, ent={sub['pred_ent'].sum()}, hyb={sub['pred_hyb_ovr'].sum()}")

