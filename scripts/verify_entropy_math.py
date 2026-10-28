import numpy as np
import math

def H_port(counts, n=50, max_cat=32):
    probs = np.array(counts, dtype=float) / n
    h_raw = -np.sum(probs * np.log2(probs + 1e-12))
    denom = math.log2(min(n, max_cat))
    return h_raw / denom

print("--- Maximum Theoretical Continuous Entropy for k Uniform Categories ---")
for k in range(15, 33):
    probs = np.ones(k) / k
    h_raw = -np.sum(probs * np.log2(probs))
    h_norm = h_raw / math.log2(32)
    print(f"k={k:2d}: max continuous H = {h_norm:.5f} (>= 0.85: {h_norm >= 0.85})")

print("\n--- Maximum Integer Partition Entropy of 50 Flows into k Categories ---")
for k in range(18, 26):
    base = 50 // k
    rem = 50 % k
    counts = [base + 1] * rem + [base] * (k - rem)
    h = H_port(counts, 50, 32)
    print(f"k={k:2d}: max integer H = {h:.5f} (counts: {rem}x{base+1} + {k-rem}x{base}) (>= 0.85: {h >= 0.85})")

