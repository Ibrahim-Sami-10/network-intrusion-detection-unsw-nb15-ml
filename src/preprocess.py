import os
import joblib
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import StandardScaler, OneHotEncoder

# Anchor directory paths to project root
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW_DIR = os.path.join(BASE_DIR, "data", "raw")
PROCESSED_DIR = os.path.join(BASE_DIR, "data", "processed")


def clean_raw_data(df: pd.DataFrame) -> pd.DataFrame:
    """Sanitizes raw UNSW-NB15 records."""
    df = df.copy()
    # Remove sequence ID column
    df.drop(columns=["id"], inplace=True, errors="ignore")

    # Standardize hyphenated or missing categorical values
    categorical_cols = ["proto", "service", "state"]
    for col in categorical_cols:
        if col in df.columns:
            df[col] = df[col].replace("-", "unknown").fillna("unknown")

    # Strip whitespace in attack category if present
    if "attack_cat" in df.columns:
        df["attack_cat"] = df["attack_cat"].astype(str).str.strip()

    return df


def run_preprocessing():
    """Fits ColumnTransformer on train partition, transforms splits, and exports CSVs."""
    print("[*] Starting Data Preprocessing Pipeline...")
    os.makedirs(PROCESSED_DIR, exist_ok=True)

    raw_train_path = os.path.join(RAW_DIR, "UNSW_NB15_training-set.csv")
    raw_test_path = os.path.join(RAW_DIR, "UNSW_NB15_testing-set.csv")

    # 1. Load Data
    print(f" -> Loading raw files from: {RAW_DIR}")
    train_df = pd.read_csv(raw_train_path)
    test_df = pd.read_csv(raw_test_path)

    # 2. Clean Data
    train_df = clean_raw_data(train_df)
    test_df = clean_raw_data(test_df)

    # 3. Separate Features and Binary Target
    X_train = train_df.drop(columns=["label", "attack_cat"], errors="ignore")
    y_train = train_df["label"]

    X_test = test_df.drop(columns=["label", "attack_cat"], errors="ignore")
    y_test = test_df["label"]

    numerical_cols = X_train.select_dtypes(
        include=["int64", "float64"]
    ).columns.tolist()
    categorical_cols = ["proto", "service", "state"]

    # 4. Fit Preprocessor (Train set only to prevent data leakage)
    preprocessor = ColumnTransformer(
        transformers=[
            ("num", StandardScaler(), numerical_cols),
            (
                "cat",
                OneHotEncoder(handle_unknown="ignore", sparse_output=False),
                categorical_cols,
            ),
        ]
    )

    print(" -> Fitting pipeline and transforming feature matrices...")
    X_train_proc = preprocessor.fit_transform(X_train)
    X_test_proc = preprocessor.transform(X_test)

    feature_names = preprocessor.get_feature_names_out()

    # 5. Export Processed Datasets as CSV
    X_train_df = pd.DataFrame(X_train_proc, columns=feature_names)
    X_test_df = pd.DataFrame(X_test_proc, columns=feature_names)

    X_train_df.to_csv(os.path.join(PROCESSED_DIR, "X_train_processed.csv"), index=False)
    X_test_df.to_csv(os.path.join(PROCESSED_DIR, "X_test_processed.csv"), index=False)
    y_train.to_csv(
        os.path.join(PROCESSED_DIR, "y_train.csv"), index=False, header=["label"]
    )
    y_test.to_csv(
        os.path.join(PROCESSED_DIR, "y_test.csv"), index=False, header=["label"]
    )

    # 6. Save Preprocessor Pipeline
    pipeline_path = os.path.join(PROCESSED_DIR, "preprocessor.joblib")
    joblib.dump(preprocessor, pipeline_path)

    print(f"[+] Preprocessing complete. Pipeline artifact saved to: {pipeline_path}")


if __name__ == "__main__":
    run_preprocessing()
