import os
import shutil

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKUP_DIR = os.path.join(_ROOT, "backup", "leakage_contaminated_baseline")
os.makedirs(BACKUP_DIR, exist_ok=True)

files_to_backup = [
    ("scripts/ingest_authentic_insdn.py", "ingest_authentic_insdn.py"),
    ("scripts/evaluate_loato_real_data.py", "evaluate_loato_real_data.py"),
    ("scripts/verify_loato_results_independently.py", "verify_loato_results_independently.py"),
    ("configs/real_data_experiment.json", "real_data_experiment.json"),
    ("reports/real_data_provenance.md", "real_data_provenance.md"),
    ("reports/loato_real_data_results.md", "loato_real_data_results.md"),
    ("reports/loato_independent_forensic_audit.md", "loato_independent_forensic_audit.md"),
    ("results/loato_real_data_metrics.csv", "loato_real_data_metrics.csv"),
    ("results/loato_independent_recomputed_metrics.csv", "loato_independent_recomputed_metrics.csv"),
    ("data/authentic_insdn_mapped.csv", "authentic_insdn_mapped.csv")
]

for src_rel, dst_name in files_to_backup:
    src = os.path.join(_ROOT, src_rel)
    dst = os.path.join(BACKUP_DIR, dst_name)
    if os.path.exists(src):
        shutil.copy2(src, dst)
        print(f"Backed up: {src_rel} -> backup/leakage_contaminated_baseline/{dst_name}")
    else:
        print(f"Warning: source file not found: {src}")

# Write metadata manifest
manifest = f"""# LEAKAGE_CONTAMINATED Baseline Manifest
Archived: October 24, 2026
Reason: Preserved forensic baseline containing target-conditioned feature engineering.
Files preserved:
- {len(files_to_backup)} files backed up
- Raw InSDN Zip SHA-256: ee89ec66705c529fef26b27dd18c6aa56d469006f7ade9cd92fd4a503e320d7d
- Benchmark File: authentic_insdn_mapped.csv (5,000 samples)
- Results: loato_real_data_metrics.csv (80 runs), loato_independent_recomputed_metrics.csv (120 runs)
"""
with open(os.path.join(BACKUP_DIR, "MANIFEST.md"), "w") as f:
    f.write(manifest)
print("[OK] Manifest written to backup/leakage_contaminated_baseline/MANIFEST.md")

