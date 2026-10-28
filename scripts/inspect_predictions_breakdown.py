import pandas as pd

df = pd.read_csv("results/task6_per_observation_predictions.csv")
print("Total rows:", len(df))
print("\nPer-seed row counts:")
print(df.groupby("seed").size())
print("\nPer-seed and per-label counts:")
print(df.groupby(["seed", "y_true"]).size())

