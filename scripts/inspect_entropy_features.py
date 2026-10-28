import pandas as pd
import numpy as np

df = pd.read_csv("data/authentic_insdn_leakage_free.csv")
print("Columns:", df.columns.tolist())

# Check probe windows
probe = df[df["attack_type"] == "PROBE"].copy()
print(f"Total probe: {len(probe)}")

for col in ["dst_entropy", "packet_entropy", "src_entropy", "flow_entropy", "byte_entropy"]:
    if col in df.columns:
        ge_085 = (probe[col] >= 0.85).sum()
        print(f"Column '{col}' >= 0.85 in PROBE: {ge_085} / {len(probe)}")
        by_src = probe.groupby("capture_source")[col].apply(lambda s: (s >= 0.85).sum())
        print(f"  by source: {dict(by_src)}")

