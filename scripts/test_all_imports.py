import os
import sys
import importlib
import traceback
from pathlib import Path

# Ensure repo root is in sys.path
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

# Core packages of IntelliShield SDN to test for clean imports
CORE_PACKAGES = [
    "advanced_analytics",
    "alerting",
    "alerts",
    "controller",
    "correlation",
    "dashboard",
    "entropy_engine",
    "evaluation",
    "fusion",
    "mitigation",
    "ml_models",
    "online_automl",
    "rca",
    "rl_engine",
    "shared_contracts",
    "ssl_zero_day",
    "traffic_generator",
    "twin",
    "verification",
    "xai",
]

def check_all_imports():
    print(f"Scanning Python modules across core packages in {REPO_ROOT}...", flush=True)
    errors = []
    success_count = 0

    for pkg_dir_name in CORE_PACKAGES:
        pkg_path = REPO_ROOT / pkg_dir_name
        if not pkg_path.is_dir():
            print(f"[WARN] Package directory not found: {pkg_dir_name}", flush=True)
            continue

        for py_file in sorted(pkg_path.rglob("*.py")):
            rel_path = py_file.relative_to(REPO_ROOT)
            parts = rel_path.parts
            
            if any(p.startswith(".") or p == "__pycache__" for p in parts):
                continue

            mod_parts = list(parts[:-1]) + [py_file.stem]
            if mod_parts[-1] == "__init__":
                mod_parts.pop()
            
            if not mod_parts:
                continue

            mod_name = ".".join(mod_parts)
            try:
                importlib.import_module(mod_name)
                print(f"  [OK] {mod_name}", flush=True)
                success_count += 1
            except Exception as e:
                err_msg = f"[{rel_path}] {type(e).__name__}: {e}"
                print(f"  [FAIL] {mod_name} -> {e}", flush=True)
                errors.append((str(rel_path), err_msg, traceback.format_exc()))

    # Also test attack.py and health_check.py
    for standalone in ["attack", "health_check"]:
        try:
            importlib.import_module(standalone)
            print(f"  [OK] {standalone}", flush=True)
            success_count += 1
        except Exception as e:
            err_msg = f"[{standalone}.py] {type(e).__name__}: {e}"
            print(f"  [FAIL] {standalone} -> {e}", flush=True)
            errors.append((standalone, err_msg, traceback.format_exc()))

    print(f"\nAudit complete: {success_count} modules successfully imported, {len(errors)} errors.", flush=True)
    if errors:
        print("\n=== IMPORT ERRORS DETECTED ===", flush=True)
        for path, msg, tb in errors:
            print(f"\n--- {path} ---", flush=True)
            print(msg, flush=True)
            print(tb, flush=True)
        return False
    else:
        print("\nAll project modules imported cleanly with NO missing libraries or syntax errors!", flush=True)
        return True

if __name__ == "__main__":
    success = check_all_imports()
    sys.exit(0 if success else 1)

