import os
import joblib
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import recall_score

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROCESSED_DIR = os.path.join(BASE_DIR, "data", "processed")
MODELS_DIR = os.path.join(BASE_DIR, "models")


def train_and_select_model():
    """Benchmarks models on processed data and serializes the winning classifier."""
    print("[*] Starting Model Training Pipeline...")
    os.makedirs(MODELS_DIR, exist_ok=True)

    # 1. Load Processed Features
    X_train = pd.read_csv(os.path.join(PROCESSED_DIR, "X_train_processed.csv"))
    y_train = pd.read_csv(os.path.join(PROCESSED_DIR, "y_train.csv"))["label"].values
    X_test = pd.read_csv(os.path.join(PROCESSED_DIR, "X_test_processed.csv"))
    y_test = pd.read_csv(os.path.join(PROCESSED_DIR, "y_test.csv"))["label"].values

    # 2. Candidate Models
    candidates = {
        "Logistic Regression": LogisticRegression(max_iter=1000, random_state=42),
        "Decision Tree": DecisionTreeClassifier(max_depth=12, random_state=42),
        "Random Forest": RandomForestClassifier(
            n_estimators=100, max_depth=15, n_jobs=-1, random_state=42
        ),
    }

    best_model = None
    best_model_name = ""
    highest_recall = -1.0

    # 3. Train & Evaluate for Attack Recall (Minimizing False Negatives)
    for name, clf in candidates.items():
        print(f" -> Training {name}...")
        clf.fit(X_train, y_train)
        y_pred = clf.predict(X_test)
        rec = recall_score(y_test, y_pred, zero_division=0)
        print(f"    - {name} Attack Recall: {rec:.4f}")

        if rec > highest_recall:
            highest_recall = rec
            best_model_name = name
            best_model = clf

    print(
        f"\n[+] Champion Architecture Selected: {best_model_name} (Recall: {highest_recall:.4f})"
    )

    # 4. Save Champion Model
    export_path = os.path.join(MODELS_DIR, "best_model.joblib")
    joblib.dump(best_model, export_path)
    print(f"[+] Model artifact exported to: {export_path}")


if __name__ == "__main__":
    train_and_select_model()
