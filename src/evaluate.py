import os
import json
import joblib
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROCESSED_DIR = os.path.join(BASE_DIR, "data", "processed")
MODELS_DIR = os.path.join(BASE_DIR, "models")
STATIC_DIR = os.path.join(BASE_DIR, "static")


def evaluate_model():
    """Evaluates benchmark models, generates confusion matrix, and updates metrics_summary.json."""
    print("[*] Running Security Evaluation Pipeline...")
    os.makedirs(STATIC_DIR, exist_ok=True)
    os.makedirs(MODELS_DIR, exist_ok=True)

    # 1. Load Processed Datasets
    X_train = pd.read_csv(os.path.join(PROCESSED_DIR, "X_train_processed.csv"))
    y_train = pd.read_csv(os.path.join(PROCESSED_DIR, "y_train.csv"))["label"].values
    X_test = pd.read_csv(os.path.join(PROCESSED_DIR, "X_test_processed.csv"))
    y_test = pd.read_csv(os.path.join(PROCESSED_DIR, "y_test.csv"))["label"].values

    # 2. Benchmark All Models for the Dashboard Table
    candidates = {
        "Logistic Regression": LogisticRegression(max_iter=1000, random_state=42),
        "Decision Tree": DecisionTreeClassifier(max_depth=12, random_state=42),
        "Random Forest": RandomForestClassifier(
            n_estimators=100, max_depth=15, n_jobs=-1, random_state=42
        ),
    }

    metrics = {}
    for name, clf in candidates.items():
        clf.fit(X_train, y_train)
        preds = clf.predict(X_test)
        metrics[name] = {
            "Accuracy": float(accuracy_score(y_test, preds)),
            "Precision": float(precision_score(y_test, preds, zero_division=0)),
            "Recall": float(recall_score(y_test, preds, zero_division=0)),
            "F1-Score": float(f1_score(y_test, preds, zero_division=0)),
        }

    # 3. Export Metrics JSON for app.py
    metrics_path = os.path.join(MODELS_DIR, "metrics_summary.json")
    with open(metrics_path, "w") as f:
        json.dump(metrics, f, indent=4)
    print(f"[+] Multi-model metrics successfully saved to: {metrics_path}")

    # 4. Evaluate Champion Model & Plot Confusion Matrix
    champion_path = os.path.join(MODELS_DIR, "best_model.joblib")
    if os.path.exists(champion_path):
        champion = joblib.load(champion_path)
    else:
        champion = candidates["Random Forest"]
        joblib.dump(champion, champion_path)

    y_best_pred = champion.predict(X_test)
    cm = confusion_matrix(y_test, y_best_pred)

    plt.figure(figsize=(6, 5))
    sns.heatmap(
        cm,
        annot=True,
        fmt="d",
        cmap="Blues",
        xticklabels=["Normal (0)", "Attack (1)"],
        yticklabels=["Normal (0)", "Attack (1)"],
    )
    plt.title(f"Confusion Matrix: {type(champion).__name__}")
    plt.ylabel("Actual Label")
    plt.xlabel("Predicted Label")
    plt.tight_layout()

    cm_path = os.path.join(STATIC_DIR, "confusion_matrix.png")
    plt.savefig(cm_path, dpi=300)
    plt.close()
    print(f"[+] Confusion matrix plot saved to: {cm_path}")

    print("\n--- Detailed Security Classification Report (Champion) ---")
    print(classification_report(y_test, y_best_pred, target_names=["Normal", "Attack"]))


if __name__ == "__main__":
    evaluate_model()
