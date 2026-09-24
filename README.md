# Enterprise AI-Powered Network Intrusion Detection System (NIDS)

An end-to-end **Machine Learning-based Network Intrusion Detection System (NIDS)** built using the **UNSW-NB15 dataset**. The system trains multiple classification models, evaluates their performance, selects a champion model, and provides an interactive **Streamlit SOC-style dashboard** for network traffic inspection and threat detection.

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-Live%20Demo-red.svg)](https://securenet-nids.streamlit.app/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

![NIDS Dashboard Demo](https://github.com/user-attachments/assets/eae334e0-66c1-4a46-bd30-b22cee6d46cc)

## 🚀 Live Demo

**Try the deployed Streamlit dashboard:**

👉 https://securenet-nids.streamlit.app/

The application allows users to inspect network-flow CSV files and simulate individual network packets for malicious/normal traffic classification.

---

## 📌 Project Overview

Network attacks can generate traffic patterns that are difficult to identify manually. This project uses supervised machine learning to classify network traffic as:

* **0 → Normal / Benign**
* **1 → Malicious / Attack**

The system trains and compares three machine-learning models:

1. Logistic Regression
2. Decision Tree
3. Random Forest

The models are evaluated using accuracy, precision, recall, and F1-score, with particular attention to **attack recall**, since missing a malicious connection can be more costly than generating a false alarm.

---

## 🏗️ System Architecture

```text
                    UNSW-NB15 Dataset
                           │
                           ▼
                ┌─────────────────────┐
                │   Data Preprocessing │
                │                     │
                │ • Missing values    │
                │ • Categorical data  │
                │ • StandardScaler    │
                │ • One-Hot Encoding  │
                └──────────┬──────────┘
                           │
                           ▼
                ┌─────────────────────┐
                │   Model Training    │
                │                     │
                │ • Logistic Reg.     │
                │ • Decision Tree     │
                │ • Random Forest     │
                └──────────┬──────────┘
                           │
                           ▼
                ┌─────────────────────┐
                │     Evaluation      │
                │                     │
                │ Accuracy            │
                │ Precision           │
                │ Recall              │
                │ F1-Score            │
                └──────────┬──────────┘
                           │
                           ▼
                ┌─────────────────────┐
                │ Best Model      │
                │ best_model.joblib   │
                └──────────┬──────────┘
                           │
                           ▼
                ┌─────────────────────┐
                │ Streamlit Dashboard │
                │                     │
                │ • CSV Inspection    │
                │ • Packet Simulation │
                │ • Metrics           │
                │ • Visualizations    │
                └─────────────────────┘
```

---

## ✨ Key Features

### 🔹 Machine Learning Classification

* Logistic Regression
* Decision Tree
* Random Forest
* Binary network-traffic classification
* Model comparison using standard classification metrics
* Champion model saved using Joblib

### 🔹 Data Preprocessing

* Numerical feature scaling using `StandardScaler`
* Categorical feature encoding using `OneHotEncoder`
* Unknown categorical values handled safely
* Training-fitted preprocessing pipeline reused during inference
* Separate training and testing datasets

### 🔹 Threat Detection

The dashboard supports:

* **Batch CSV Inspection**
* **Single Packet Simulation**
* Prediction of Normal vs Malicious traffic
* Prediction confidence when supported by the model
* Evaluation metrics when ground-truth labels are included in the uploaded CSV

### 🔹 Security Operations Dashboard

The Streamlit dashboard provides:

* Overview metrics
* Model performance visualization
* Confusion matrix
* Classification metrics
* Threat detection interface
* Packet simulation
* Interactive network-traffic inspection

---

## 📊 Benchmark Results

The three machine-learning models were compared using the UNSW-NB15 testing data.

| Model               |   Accuracy |     Recall |  Precision |   F1-Score |
| ------------------- | ---------: | ---------: | ---------: | ---------: |
| Logistic Regression |     81.20% |     78.40% |     84.10% |     81.10% |
| Decision Tree       |     86.80% |     88.20% |     87.40% |     87.80% |
| **Random Forest**   | **90.25%** | **86.69%** | **98.85%** | **92.37%** |

### Why Recall Matters

For an intrusion detection system, **recall is particularly important** because it measures how many actual malicious connections are successfully detected.

A model with poor recall may allow real attacks to pass through undetected.

At the same time, precision is important because excessive false positives can overwhelm security analysts with unnecessary alerts.

---

## 📈 Evaluation Metrics

| Metric           | Description                                                    |
| ---------------- | -------------------------------------------------------------- |
| Accuracy         | Percentage of all correctly classified network connections.    |
| Precision        | Percentage of predicted attacks that were actually malicious.  |
| Recall           | Percentage of actual malicious connections correctly detected. |
| F1-Score         | Harmonic mean of precision and recall.                         |
| Confusion Matrix | Shows correct and incorrect predictions for each class.        |

The evaluation script generates the detailed metrics and stores them in:

```text
models/metrics_summary.json
```

A confusion-matrix visualization is generated at:

```text
static/confusion_matrix.png
```

---

## 🖥️ Streamlit SOC Dashboard

The deployed Streamlit dashboard combines monitoring, visualization, and inference into a single interface.

### 1. Overview Dashboard

Displays the project's main model and dataset information.

### 2. Visualizations & Metrics

Provides:

* Model evaluation metrics
* Classification results
* Confusion matrix
* Performance comparison

### 3. Threat Detection

#### Batch CSV Inspection

Users can upload a CSV containing UNSW-NB15-compatible network-flow features.

The application:

1. Reads the uploaded CSV.
2. Removes non-feature columns such as `id`, `label`, and `attack_cat` when present.
3. Cleans categorical features.
4. Applies the saved preprocessing pipeline.
5. Generates predictions using the trained model.
6. Displays `NORMAL` or `MALICIOUS` classifications.
7. Displays prediction confidence when supported.
8. Calculates evaluation metrics when ground-truth labels are available.

#### Single Packet Simulation

Users can manually enter selected network-flow characteristics such as:

* Duration
* Source packets
* Destination packets
* Source bytes
* Destination bytes
* Protocol
* Service
* Connection state
* Rate
* Source TTL

The remaining required features are populated using the application's simulation defaults before the trained model performs inference.

---

## 📂 Dataset

This project uses the **UNSW-NB15 dataset**, a widely used benchmark dataset for network intrusion detection research.

The dataset contains normal network traffic and multiple categories of attacks, including:

* Fuzzers
* Analysis
* Backdoors
* DoS
* Exploits
* Generic
* Reconnaissance
* Shellcode
* Worms

### Dataset Size

| Dataset      |     Records |
| ------------ | ----------: |
| Training Set |     175,341 |
| Testing Set  |      82,332 |
| **Total**    | **257,673** |

Dataset source:

https://research.unsw.edu.au/projects/unsw-nb15-dataset

---

## 🔬 Machine Learning Pipeline

### Step 1 — Data Loading

The training and testing CSV files are loaded from:

```text
data/raw/
```

### Step 2 — Data Cleaning

The preprocessing script:

* Removes the `id` column.
* Cleans categorical values.
* Handles missing categorical values.
* Separates the target `label`.
* Removes `attack_cat` from the binary classification features.

### Step 3 — Feature Transformation

Numerical features are transformed using:

```python
StandardScaler()
```

Categorical features are transformed using:

```python
OneHotEncoder(handle_unknown="ignore", sparse_output=False)
```

The transformations are combined using a `ColumnTransformer`.

### Step 4 — Model Training

The project trains:

```text
Logistic Regression
Decision Tree
Random Forest
```

### Step 5 — Model Evaluation

The models are evaluated on the testing dataset using:

* Accuracy
* Precision
* Recall
* F1-score
* Confusion Matrix

### Step 6 — Model Saving

The selected model is saved as:

```text
models/best_model.joblib
```

The fitted preprocessing pipeline is saved as:

```text
data/processed/preprocessor.joblib
```

---

## 📁 Project Structure

```text
network-intrusion-detection-unsw-nb15-ml/
│
├── app.py
├── requirements.txt
├── README.md
├── LICENSE
│
├── data/
│   ├── raw/
│   │   ├── UNSW_NB15_training-set.csv
│   │   └── UNSW_NB15_testing-set.csv
│   │
│   └── processed/
│       ├── X_train_processed.csv
│       ├── X_test_processed.csv
│       ├── y_train.csv
│       ├── y_test.csv
│       └── preprocessor.joblib
│
├── models/
│   ├── best_model.joblib
│   └── metrics_summary.json
│
├── src/
│   ├── preprocess.py
│   ├── train.py
│   └── evaluate.py
│
└── static/
    └── confusion_matrix.png
```

---

## ⚙️ Installation

### 1. Clone the Repository

```bash
git clone https://github.com/Ibrahim-Sami-10/network-intrusion-detection-unsw-nb15-ml.git
cd network-intrusion-detection-unsw-nb15-ml
```

### 2. Create a Virtual Environment

```bash
python -m venv venv
```

Activate it on Windows:

```bash
venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

---

## ▶️ Running the Project

### Step 1 — Preprocess the Dataset

```bash
python src/preprocess.py
```

This creates the processed training/testing datasets and saves the fitted preprocessing pipeline.

### Step 2 — Train the Models

```bash
python src/train.py
```

This trains the three candidate models and saves the selected model to:

```text
models/best_model.joblib
```

### Step 3 — Generate Evaluation Results

```bash
python src/evaluate.py
```

This generates:

```text
models/metrics_summary.json
static/confusion_matrix.png
```

### Step 4 — Launch the Dashboard

```bash
streamlit run app.py
```

The dashboard will then be available locally through Streamlit.

---

## 🛠️ Technologies Used

| Technology   | Purpose                                  |
| ------------ | ---------------------------------------- |
| Python       | Core programming language                |
| Pandas       | Data loading and manipulation            |
| NumPy        | Numerical computation                    |
| Scikit-learn | Machine learning and preprocessing       |
| Matplotlib   | Data visualization                       |
| Seaborn      | Statistical visualization                |
| Joblib       | Model and preprocessing serialization    |
| Streamlit    | Interactive web dashboard                |
| Jupyter      | Exploratory analysis and experimentation |

---

## 🔐 Security Use Case

The system is designed as an educational and research-oriented NIDS prototype.

A typical workflow is:

```text
Network Traffic
      │
      ▼
Feature Extraction
      │
      ▼
Preprocessing
      │
      ▼
Machine Learning Model
      │
      ├───────────────┐
      ▼               ▼
   NORMAL         MALICIOUS
                      │
                      ▼
                Security Alert
```

The system can therefore serve as a foundation for experimenting with machine-learning-based network intrusion detection.

---

## ⚠️ Limitations

This implementation has several practical limitations:

* It operates on **CSV network-flow data**, rather than directly capturing live network packets.
* The single-packet interface is a **simulation**, not a live packet-capture system.
* The model is trained specifically using the UNSW-NB15 dataset.
* Performance on real-world network traffic may differ from benchmark results.
* The system is a machine-learning prototype and should not be treated as a production enterprise IDS without additional validation.
* The current implementation performs binary classification rather than directly predicting individual attack categories.

---

## 🔮 Future Improvements

Possible future improvements include:

* Live packet capture using tools such as Scapy or Zeek
* Real-time network monitoring
* Multi-class attack classification
* Explainable AI using SHAP
* Automated security alerts
* Database-backed threat history
* User authentication and role-based access
* Continuous model retraining
* Model drift monitoring
* Integration with SIEM platforms
* Containerized deployment using Docker

---

## 📄 License

This project is released under the **MIT License**.

See the [LICENSE](LICENSE) file for details.
