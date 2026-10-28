import pandas as pd
import numpy as np

bench_df = pd.read_csv("data/authentic_insdn_leakage_free.csv")
bench_df["raw_window_id"] = np.arange(len(bench_df))

print("Benchmark length:", len(bench_df))
print("Classes in benchmark:")
print(bench_df["attack_type"].value_counts())

# Probe windows
probe_df = bench_df[bench_df["attack_type"] == "PROBE"]
print("\nProbe windows:")
print("Total probe windows:", len(probe_df))
print("Probe sources:", probe_df["capture_source"].value_counts().to_dict())
print("Probe unique session groups:", probe_df["session_group"].nunique())
print("Probe sessions per source:", probe_df.groupby("capture_source")["session_group"].nunique().to_dict())

# Normal windows
norm_df = bench_df[bench_df["attack_type"] == "NORMAL"]
print("\nNormal windows:")
print("Total normal windows:", len(norm_df))
print("Normal sources:", norm_df["capture_source"].value_counts().to_dict())
print("Normal unique session groups:", norm_df["session_group"].nunique())

