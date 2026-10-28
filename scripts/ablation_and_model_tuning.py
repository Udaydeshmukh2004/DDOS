"""
IntelliShield SDN — Feature Engineering Ablation & Multi-Model Tuning
Evaluates feature subsets and classifiers using leakage-free cross-validation.
"""

import os
import sys
import json
import csv
import numpy as np
from sklearn.model_selection import StratifiedKFold
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier, ExtraTreesClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)

from ml_models.feature_builder import FEATURE_NAMES

FEATURE_CONFIGS = {
    "Config_A_All_15": FEATURE_NAMES,
    "Config_B_No_Duration": [f for f in FEATURE_NAMES if f != "duration_mean"],
    "Config_C_No_Duration_No_FlowCount": [f for f in FEATURE_NAMES if f not in ("duration_mean", "flow_count")],
    "Config_D_Justified_Robust": [
        "packet_rate_mean", "packet_rate_max", "byte_rate_mean", "byte_rate_max",
        "unique_src_count", "unique_dst_count", "src_entropy", "dst_entropy",
        "packet_entropy", "entropy_score", "flow_concentration"
    ],
}

def load_data():
    features_csv = os.path.join(_ROOT, "logs", "ml_features.csv")
    rows, labels, timestamps = [], [], []
    with open(features_csv, "r") as f:
        reader = csv.DictReader(f)
        for r in reader:
            lbl = r.get("label", "").strip()
            if lbl in ("", "-1", "None"):
                continue
            try:
                y = int(float(lbl))
            except ValueError:
                continue
            rows.append(r)
            labels.append(y)
            timestamps.append(r.get("timestamp", ""))
    return rows, np.array(labels), timestamps

def get_matrix(rows, feature_list):
    matrix = []
    for r in rows:
        vec = []
        for feat in feature_list:
            try:
                vec.append(float(r.get(feat, 0.0)))
            except ValueError:
                vec.append(0.0)
        matrix.append(vec)
    return np.array(matrix)

def evaluate_cv(clf_factory, X, y, n_splits=5):
    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=42)
    accs, precs, recs, f1s = [], [], [], []
    for train_idx, val_idx in skf.split(X, y):
        X_tr, X_val = X[train_idx], X[val_idx]
        y_tr, y_val = y[train_idx], y[val_idx]
        
        # Scaling fit strictly on training fold
        scaler = StandardScaler()
        X_tr_sc = scaler.fit_transform(X_tr)
        X_val_sc = scaler.transform(X_val)
        
        clf = clf_factory()
        clf.fit(X_tr_sc, y_tr)
        preds = clf.predict(X_val_sc)
        
        accs.append(accuracy_score(y_val, preds))
        precs.append(precision_score(y_val, preds, zero_division=0))
        recs.append(recall_score(y_val, preds, zero_division=0))
        f1s.append(f1_score(y_val, preds, zero_division=0))
        
    return {
        "acc_mean": np.mean(accs),
        "prec_mean": np.mean(precs),
        "rec_mean": np.mean(recs),
        "f1_mean": np.mean(f1s),
    }

def main():
    rows, y, timestamps = load_data()
    print("=" * 70)
    print("  INTELLISHIELD SDN — FEATURE ABLATION & MODEL SELECTION")
    print("=" * 70)
    print(f"Total labeled vectors: {len(rows)} (Normal={np.sum(y==0)}, Attack={np.sum(y==1)})")
    
    # Time-ordered train/test split: first 70% for train/val, last 30% held-out test
    split_idx = int(len(rows) * 0.70)
    rows_train, rows_test = rows[:split_idx], rows[split_idx:]
    y_train, y_test = y[:split_idx], y[split_idx:]
    print(f"Train/Val partition: {len(rows_train)} samples")
    print(f"Held-Out Test      : {len(rows_test)} samples\n")

    classifiers = {
        "DecisionTree_Regularized": lambda: DecisionTreeClassifier(max_depth=4, min_samples_leaf=3, class_weight="balanced", random_state=42),
        "RandomForest": lambda: RandomForestClassifier(n_estimators=100, max_depth=5, min_samples_leaf=2, class_weight="balanced", random_state=42),
        "HistGradientBoosting": lambda: HistGradientBoostingClassifier(max_iter=100, max_leaf_nodes=15, learning_rate=0.05, class_weight="balanced", random_state=42),
        "ExtraTrees": lambda: ExtraTreesClassifier(n_estimators=100, max_depth=5, min_samples_leaf=2, class_weight="balanced", random_state=42)
    }

    results = []

    print(f"{'Feature Config':<32} {'Model':<24} {'CV Acc':<10} {'CV Prec':<10} {'CV Rec':<10} {'CV F1':<10}")
    print("-" * 96)

    for cfg_name, feat_list in FEATURE_CONFIGS.items():
        X_train_cfg = get_matrix(rows_train, feat_list)
        for clf_name, clf_fn in classifiers.items():
            cv_res = evaluate_cv(clf_fn, X_train_cfg, y_train)
            print(f"{cfg_name:<32} {clf_name:<24} {cv_res['acc_mean']*100:6.2f}%   {cv_res['prec_mean']*100:6.2f}%   {cv_res['rec_mean']*100:6.2f}%   {cv_res['f1_mean']*100:6.2f}%")
            results.append({
                "config": cfg_name,
                "model": clf_name,
                "n_features": len(feat_list),
                "features": feat_list,
                "cv_acc": cv_res["acc_mean"],
                "cv_prec": cv_res["prec_mean"],
                "cv_rec": cv_res["rec_mean"],
                "cv_f1": cv_res["f1_mean"],
            })

    # Find champion model on validation F1
    best_res = max(results, key=lambda r: r["cv_f1"])
    print("\n" + "=" * 70)
    print(f"CHAMPION MODEL (Selected on Validation CV F1):")
    print(f"  Configuration: {best_res['config']} ({best_res['n_features']} features)")
    print(f"  Model        : {best_res['model']}")
    print(f"  Validation F1: {best_res['cv_f1']*100:.2f}% (Recall={best_res['cv_rec']*100:.2f}%, Precision={best_res['cv_prec']*100:.2f}%)")
    print("=" * 70)

    # Now evaluate champion on untouched held-out test set
    best_feat_list = best_res["features"]
    X_train_best = get_matrix(rows_train, best_feat_list)
    X_test_best = get_matrix(rows_test, best_feat_list)

    scaler_best = StandardScaler()
    X_tr_sc = scaler_best.fit_transform(X_train_best)
    X_te_sc = scaler_best.transform(X_test_best)

    champion_clf = classifiers[best_res["model"]]()
    champion_clf.fit(X_tr_sc, y_train)
    test_preds = champion_clf.predict(X_te_sc)

    tn, fp, fn, tp = confusion_matrix(y_test, test_preds, labels=[0, 1]).ravel()
    t_acc = accuracy_score(y_test, test_preds)
    t_prec = precision_score(y_test, test_preds, zero_division=0)
    t_rec = recall_score(y_test, test_preds, zero_division=0)
    t_f1 = f1_score(y_test, test_preds, zero_division=0)
    t_fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    t_spec = tn / (tn + fp) if (tn + fp) > 0 else 0.0
    t_bal_acc = (t_rec + t_spec) / 2.0

    print("\n--- CHAMPION EVALUATION ON HELD-OUT TEST SET ---")
    print(f"Confusion Matrix: TP={tp}, FP={fp}, TN={tn}, FN={fn}")
    print(f"Accuracy        : {t_acc*100:.2f}%")
    print(f"Precision       : {t_prec*100:.2f}%")
    print(f"Recall          : {t_rec*100:.2f}%")
    print(f"F1-Score        : {t_f1*100:.2f}%")
    print(f"FPR             : {t_fpr*100:.2f}%")
    print(f"Specificity     : {t_spec*100:.2f}%")
    print(f"Balanced Acc    : {t_bal_acc*100:.2f}%")

    # Save ablation results to JSON for reporting
    out_json = os.path.join(_ROOT, "logs", "ablation_study_results.json")
    with open(out_json, "w") as f:
        json.dump({
            "results": results,
            "champion": best_res,
            "test_evaluation": {
                "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn),
                "accuracy": round(t_acc, 4),
                "precision": round(t_prec, 4),
                "recall": round(t_rec, 4),
                "f1_score": round(t_f1, 4),
                "fpr": round(t_fpr, 4),
                "specificity": round(t_spec, 4),
                "balanced_accuracy": round(t_bal_acc, 4),
            }
        }, f, indent=2)
    print(f"\nSaved ablation study report to: {out_json}")

if __name__ == "__main__":
    main()

