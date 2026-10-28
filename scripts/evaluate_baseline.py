"""
IntelliShield SDN — Baseline Model Evaluator
Evaluates the original baseline models (decision_tree.pkl, isolation_forest.pkl, scaler.pkl)
on the existing dataset before any modifications are made.
"""

import os
import sys
import pickle
import csv
import numpy as np
from sklearn.metrics import confusion_matrix, classification_report, accuracy_score, precision_score, recall_score, f1_score

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

from ml_models.feature_builder import FEATURE_NAMES

def load_data():
    features_csv = os.path.join(_ROOT, "logs", "ml_features.csv")
    X, y, timestamps = [], [], []
    with open(features_csv, "r") as f:
        reader = csv.DictReader(f)
        for row in reader:
            lbl = row.get("label", "").strip()
            if lbl in ("", "-1", "None"):
                continue
            try:
                y_val = int(float(lbl))
            except ValueError:
                continue
            vec = []
            for feat in FEATURE_NAMES:
                try:
                    vec.append(float(row.get(feat, 0.0)))
                except ValueError:
                    vec.append(0.0)
            X.append(vec)
            y.append(y_val)
            timestamps.append(row.get("timestamp", ""))
    return np.array(X), np.array(y), timestamps

def evaluate_baseline():
    print("=" * 65)
    print("  INTELLISHIELD SDN — ORIGINAL BASELINE EVALUATION")
    print("=" * 65)

    models_dir = os.path.join(_ROOT, "logs", "models_baseline_original")
    dt_path = os.path.join(models_dir, "decision_tree.pkl")
    iso_path = os.path.join(models_dir, "isolation_forest.pkl")
    scaler_path = os.path.join(models_dir, "scaler.pkl")

    if not os.path.exists(dt_path) or not os.path.exists(scaler_path):
        print(f"Error: Baseline models missing in {models_dir}")
        return

    with open(dt_path, "rb") as f:
        dt = pickle.load(f)
    with open(scaler_path, "rb") as f:
        scaler = pickle.load(f)
    iso = None
    if os.path.exists(iso_path):
        with open(iso_path, "rb") as f:
            iso = pickle.load(f)

    X, y, timestamps = load_data()
    print(f"Loaded dataset: {len(X)} samples (Normal={np.sum(y==0)}, Attack={np.sum(y==1)})")

    # Time-ordered split: 70% train/val, 30% held-out test to prevent time-series leakage
    split_idx = int(len(X) * 0.70)
    X_train, X_test = X[:split_idx], X[split_idx:]
    y_train, y_test = y[:split_idx], y[split_idx:]
    ts_test = timestamps[split_idx:]

    print(f"Train partition: {len(X_train)} samples (Normal={np.sum(y_train==0)}, Attack={np.sum(y_train==1)})")
    print(f"Test partition : {len(X_test)} samples (Normal={np.sum(y_test==0)}, Attack={np.sum(y_test==1)})")

    # 1. Decision Tree Evaluation
    X_test_scaled = scaler.transform(X_test)
    y_pred_dt = dt.predict(X_test_scaled)

    tn, fp, fn, tp = confusion_matrix(y_test, y_pred_dt, labels=[0, 1]).ravel()
    acc = accuracy_score(y_test, y_pred_dt)
    prec = precision_score(y_test, y_pred_dt, zero_division=0)
    rec = recall_score(y_test, y_pred_dt, zero_division=0)
    f1 = f1_score(y_test, y_pred_dt, zero_division=0)
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    spec = tn / (tn + fp) if (tn + fp) > 0 else 0.0
    bal_acc = (rec + spec) / 2.0

    print("\n--- BASELINE DECISION TREE (Held-Out Test Set) ---")
    print(f"Confusion Matrix: TP={tp}, FP={fp}, TN={tn}, FN={fn}")
    print(f"Accuracy        : {acc*100:.2f}%")
    print(f"Precision       : {prec*100:.2f}%")
    print(f"Recall          : {rec*100:.2f}%")
    print(f"F1-Score        : {f1*100:.2f}%")
    print(f"FPR             : {fpr*100:.2f}%")
    print(f"Specificity     : {spec*100:.2f}%")
    print(f"Balanced Acc    : {bal_acc*100:.2f}%")

    # Feature Importance of Baseline Tree
    print("\nBaseline Feature Importances:")
    importances = sorted(zip(FEATURE_NAMES, dt.feature_importances_), key=lambda x: x[1], reverse=True)
    for name, imp in importances:
        if imp > 0.001:
            bar = "█" * int(imp * 40)
            print(f"  {name:22s} {imp:.4f}  {bar}")

    # 2. Isolation Forest Evaluation
    if iso is not None:
        raw_scores = iso.decision_function(X_test_scaled)
        # In sklearn IF: negative = anomaly (attack=1), positive = normal (normal=0)
        y_pred_iso = (raw_scores < 0).astype(int)
        tn_i, fp_i, fn_i, tp_i = confusion_matrix(y_test, y_pred_iso, labels=[0, 1]).ravel()
        rec_i = recall_score(y_test, y_pred_iso, zero_division=0)
        prec_i = precision_score(y_test, y_pred_iso, zero_division=0)
        f1_i = f1_score(y_test, y_pred_iso, zero_division=0)
        acc_i = accuracy_score(y_test, y_pred_iso)
        fpr_i = fp_i / (fp_i + tn_i) if (fp_i + tn_i) > 0 else 0.0

        print("\n--- BASELINE ISOLATION FOREST (Default Threshold 0.0) ---")
        print(f"Confusion Matrix: TP={tp_i}, FP={fp_i}, TN={tn_i}, FN={fn_i}")
        print(f"Accuracy        : {acc_i*100:.2f}%")
        print(f"Precision       : {prec_i*100:.2f}%")
        print(f"Recall          : {rec_i*100:.2f}%")
        print(f"F1-Score        : {f1_i*100:.2f}%")
        print(f"FPR             : {fpr_i*100:.2f}%")

    print("=" * 65)

if __name__ == "__main__":
    evaluate_baseline()

