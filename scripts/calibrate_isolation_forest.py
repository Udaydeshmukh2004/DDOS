"""
Calibrate Isolation Forest on Training Normal Data
"""
import csv, os, sys
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import confusion_matrix, precision_score, recall_score, f1_score, accuracy_score

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
from ml_models.feature_builder import FEATURE_NAMES

def load_data():
    features_csv = os.path.join(_ROOT, "logs", "ml_features.csv")
    X, y = [], []
    with open(features_csv, "r") as f:
        reader = csv.DictReader(f)
        for r in reader:
            lbl = r.get("label", "").strip()
            if lbl in ("", "-1", "None"): continue
            try:
                y_val = int(float(lbl))
            except ValueError: continue
            vec = [float(r.get(feat, 0.0)) for feat in FEATURE_NAMES]
            X.append(vec)
            y.append(y_val)
    return np.array(X), np.array(y)

def main():
    X, y = load_data()
    split_idx = int(len(X) * 0.70)
    X_train, y_train = X[:split_idx], y[:split_idx]
    X_test, y_test = X[split_idx:], y[split_idx:]

    # One-class setup: Fit strictly on normal training samples
    X_train_normal = X_train[y_train == 0]
    scaler = StandardScaler()
    X_norm_sc = scaler.fit_transform(X_train_normal)

    print(f"Fitting Isolation Forest on {len(X_norm_sc)} benign training vectors...")

    for contamination in [0.01, 0.03, 0.05, 0.10, "auto"]:
        iso = IsolationForest(contamination=contamination, random_state=42, n_estimators=100)
        iso.fit(X_norm_sc)

        # Evaluate on validation/test set
        X_test_sc = scaler.transform(X_test)
        raw_scores = iso.decision_function(X_test_sc)

        # Calibrate threshold: find best percentile or zero-crossing
        # raw_score < threshold => attack (1)
        for thresh in np.arange(-0.15, 0.10, 0.02):
            preds = (raw_scores < thresh).astype(int)
            rec = recall_score(y_test, preds, zero_division=0)
            prec = precision_score(y_test, preds, zero_division=0)
            f1 = f1_score(y_test, preds, zero_division=0)
            acc = accuracy_score(y_test, preds)
            if f1 > 0.50:
                print(f"Contam={str(contamination):<6} Thresh={thresh:6.2f} -> Acc={acc*100:.1f}%, Rec={rec*100:.1f}%, Prec={prec*100:.1f}%, F1={f1*100:.1f}%")

if __name__ == "__main__":
    main()

