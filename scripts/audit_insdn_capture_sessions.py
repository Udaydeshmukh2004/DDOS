import pandas as pd
import numpy as np
import os

AUTH_DIR = "data/authentic_insdn"
files = ["Normal_data.csv", "metasploitable-2.csv", "OVS.csv"]

print("=" * 80)
print("IN-DEPTH FORENSIC AUDIT OF INSDN CAPTURE SESSIONS, TIMESTAMPS & IPS")
print("=" * 80)

for fname in files:
    fpath = os.path.join(AUTH_DIR, fname)
    print(f"\n>>> Analyzing {fname}...")
    df = pd.read_csv(fpath, usecols=['Timestamp', 'Label', 'Src IP', 'Dst IP', 'Dst Port', 'Protocol'], low_memory=False)
    
    # 1. Total rows and labels
    print(f"  Total records: {len(df)}")
    print(f"  Class distribution: {df['Label'].value_counts().to_dict()}")
    
    # 2. Timestamp analysis
    df['Timestamp'] = df['Timestamp'].astype(str).str.strip()
    n_ts = df['Timestamp'].nunique()
    print(f"  Distinct timestamps: {n_ts}")
    
    # 3. Session grouping: Timestamp x Label
    ts_lbl = df.groupby(['Timestamp', 'Label']).size().unstack(fill_value=0)
    print(f"  Active attack/traffic sessions (Timestamp x Label pairs): {len(ts_lbl)}")
    print("  Sample sessions (first 5 timestamps with label counts):")
    for ts, row in ts_lbl.head(5).iterrows():
        active = {k: v for k, v in row.to_dict().items() if v > 0}
        print(f"    - {ts}: {active}")
        
    # 4. IP diversity
    print(f"  Distinct Source IPs: {df['Src IP'].nunique()}")
    print(f"  Distinct Destination IPs: {df['Dst IP'].nunique()}")
    print(f"  Top 5 Target (Dst) IPs: {df['Dst IP'].value_counts().head(5).to_dict()}")
    print(f"  Top 5 Source IPs: {df['Src IP'].value_counts().head(5).to_dict()}")
    print(f"  Distinct Destination Ports: {df['Dst Port'].nunique()}")

