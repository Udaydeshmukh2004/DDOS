"""
Inspect Decision Tree Model and Feature Splits
"""
import pickle, os, sys
from sklearn.tree import export_text

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT)
from ml_models.feature_builder import FEATURE_NAMES

def main():
    dt_path = os.path.join(_ROOT, "logs", "models", "decision_tree.pkl")
    scaler_path = os.path.join(_ROOT, "logs", "models", "scaler.pkl")
    
    if not os.path.exists(dt_path):
        print(f"Missing {dt_path}")
        return
        
    with open(dt_path, "rb") as f:
        dt = pickle.load(f)
        
    print(f"Decision Tree Type: {type(dt)}")
    print(f"Classes: {dt.classes_}")
    print(f"Feature Importances:")
    for name, imp in zip(FEATURE_NAMES, dt.feature_importances_):
        if imp > 0.001:
            print(f"  {name:25s}: {imp:.4f}")
            
    tree_rules = export_text(dt, feature_names=FEATURE_NAMES)
    print("\nTree Structure:")
    print(tree_rules)

if __name__ == "__main__":
    main()

