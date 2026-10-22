# Enterprise AI-Powered Network Intrusion Detection System (NIDS)

An end-to-end **Machine Learning-based Network Intrusion Detection System (NIDS)** built using the **UNSW-NB15 dataset**. The system trains multiple classification models, evaluates their performance, selects a champion model, and provides an interactive **Streamlit SOC-style dashboard** for network traffic inspection, **live multi-source threat intelligence ingestion from public APIs**, and real-time threat detection.

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-Live%20Demo-red.svg)](https://securenet-nids.streamlit.app/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

![NIDS Dashboard Demo](https://github.com/user-attachments/assets/eae334e0-66c1-4a46-bd30-b22cee6d46cc)

## 🚀 Live Demo

**Try the deployed Streamlit dashboard:**

👉 https://securenet-nids.streamlit.app/

The application allows users to ingest live threat intelligence from public cybersecurity APIs (SANS ISC, abuse.ch Feodo Tracker, Emerging Threats), inspect network-flow CSV files, and simulate individual network packets for malicious/normal traffic classification.

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
                │ Best Model          │
                │ best_model.joblib   │
                └──────────┬──────────┘
                           │
                           ▼
    ┌──────────────────────────────────────────┐
    │         Streamlit SOC Dashboard          │
    │                                          │
    │  • Live Multi-Source API Ingestion        │
    │    ├─ SANS ISC Attacks & Target Ports     │
    │    ├─ abuse.ch Feodo Tracker (Botnet C2)  │
    │    ├─ Emerging Threats Compromised IPs    │
    │    ├─ Live TCP Socket Probes              │
    │    └─ Custom API Endpoint Ingestion       │
    │                                          │
    │  • Batch CSV Inspection                  │
    │  • Single Packet Simulation              │
    │  • Real-time Threat Alert Banners        │
    │  • Visualizations & Metrics              │
    └──────────────────────────────────────────┘
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

### 🔹 Threat Detection & Live Telemetry Ingestion

The dashboard supports:

* **Live Multi-Source Telemetry (Public APIs)**: Real-time ingestion and threat prediction from 4+ live public cybersecurity feeds and network probes:
  1. **SANS Internet Storm Center (ISC) Attacks Feed**: Live attacking IP addresses and scan frequencies from SANS global honeypot network (`https://isc.sans.edu/api/sources/attacks/`).
  2. **SANS ISC Target Ports Telemetry**: Real-time targeted ports, total scanned packet volumes, and scanner counts (`https://isc.sans.edu/api/topports/records/`).
  3. **abuse.ch Feodo Tracker Botnet C2**: Active botnet command-and-control servers (Emotet, Dridex, QakBot, Bumblebee) (`https://feodotracker.abuse.ch/downloads/ipblocklist.json`).
  4. **Proofpoint Emerging Threats Compromised Hosts**: Real-time compromised nodes engaged in exploit delivery (`https://rules.emergingthreats.net/blockrules/compromised-ips.txt`).
  5. **Live Network Socket Telemetry Probe**: Real-time TCP handshake and latency measurements to public DNS/HTTP endpoints (Cloudflare 1.1.1.1, Google 8.8.8.8, Quad9 9.9.9.9).
  6. **Custom API Endpoint Ingestion**: Input field to ingest live JSON or line-delimited feeds from any custom public or internal security API.
* **Batch CSV Inspection**: Upload and inspect raw flow capture files.
* **Single Packet Simulation**: Manually craft packet headers to test classification.
* **Real-time Threat Prediction**: Normal vs. Malicious classification, model confidence percentages, and severity scoring (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
* **Auto-Stream Mode**: Configurable continuous ingestion and automated threat classification at regular intervals (5s, 10s, 15s, 30s).
* **Evaluation Metrics**: Ground-truth evaluation (Accuracy, Precision, Recall, F1) when test labels are provided.

### 🔹 Security Operations Dashboard

The Streamlit dashboard provides:

* **SOC Dark Cyber Theme**: Cyber threat alert cards, severity badges, and status pills.
* **Live Ingestion & Prediction Breakdown**: Metrics and comparisons per public source feed.
* **Overview Metrics**: Packets ingested, attacks detected, normal flows, and threat ratios.
* **Real-time Threat Alerts**: Instant alert banners displaying threat IP, target port, confidence, and metadata.
* **Interactive Inspection Log Table**: Search, filter by feed, risk level, or classification, and export incident reports as CSV.
* **Visualizations**: Traffic class distributions, per-source intrusion breakdowns, and confusion matrices.

---

## 📊 Benchmark Results

The three machine-learning models were compared using the UNSW-NB15 testing data.

| Model               |   Accuracy |     Recall |  Precision |   F1-Score |
| ------------------- | ---------: | ---------: | ---------: | ---------: |
| Logistic Regression |     87.86% |     83.95% |     97.91% |     90.40% |
| Decision Tree       |     89.36% |     85.53% |     98.66% |     91.63% |
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

The deployed Streamlit dashboard combines monitoring, visualization, live threat intelligence ingestion, and inference into a single interface.

### 1. Overview Dashboard

Displays the project's main model and dataset information. When live data or batch data is active, shows real-time KPI scorecards (packets ingested, intrusions detected, attack ratio), per-source feed breakdown tables, and critical threat alert banners.

### 2. 🌐 Live Multi-Source Stream (Public APIs)

The primary live detection interface. Users can:

* **Toggle individual public feed sources** (SANS ISC Attacks, SANS ISC Target Ports, abuse.ch Feodo Tracker, Emerging Threats Compromised IPs, Live Network Socket Probes).
* **Adjust records per source** using a slider (3–30 records per feed).
* **Enable Auto-Stream Mode** for continuous ingestion at configurable intervals (5s, 10s, 15s, 30s).
* **Ingest from a custom API endpoint** (JSON lists, objects, or line-delimited IP streams).
* **View real-time threat alert cards** with attacking IP, target port, confidence %, risk level, and feed metadata.
* **Filter and search** the live inspection log by source feed, classification, IP address, or port.
* **Download incident reports** as CSV for IR/forensics workflows.

### 3. Visualizations & Metrics

Provides:

* Traffic class distribution charts
* Per-source feed intrusion breakdown (when live data is active)
* Confusion matrix (when ground-truth labels are available)
* Model performance comparison matrix

### 4. Threat Detection (Inference)

#### 🌐 Live Multi-Source Public Feeds

Quick-access tab to fetch and classify live records from all active public feeds with a single click.

#### 📁 Batch CSV Inspection

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

#### 🎯 Single Packet Simulation

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
| Training Set |      82,332 |
| Testing Set  |     175,341 |
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
├── app.py                          # Streamlit SOC dashboard (main entry point)
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
├── notebooks/
│   ├── 01_data_preprocessing_and_eda.ipynb
│   └── 02_model_training_and_evaluation.ipynb
│
├── src/
│   ├── __init__.py
│   ├── preprocess.py
│   ├── train.py
│   ├── evaluate.py
│   └── live_sources.py             # Live multi-source API ingestion engine
│
└── static/
    ├── confusion_matrix.png
    └── eda_attack_distribution.png
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

| Technology          | Purpose                                                    |
| ------------------- | ---------------------------------------------------------- |
| Python              | Core programming language                                  |
| Pandas              | Data loading and manipulation                              |
| NumPy               | Numerical computation                                      |
| Scikit-learn        | Machine learning and preprocessing                         |
| Matplotlib          | Data visualization                                         |
| Seaborn             | Statistical visualization                                  |
| Joblib              | Model and preprocessing serialization                      |
| Streamlit           | Interactive web dashboard                                  |
| Jupyter             | Exploratory analysis and experimentation                   |
| urllib / ssl / json  | Live public API ingestion (SANS ISC, abuse.ch, ET)         |
| socket              | Real-time TCP socket probes for live network telemetry     |

---

## 🔐 Security Use Case

The system is designed as an educational and research-oriented NIDS prototype with live threat intelligence capabilities.

A typical workflow is:

```text
  Live Public APIs              CSV Upload           Packet Simulation
  (SANS ISC, Feodo,             (UNSW-NB15           (Manual Header
   Emerging Threats)             flow data)            Input)
        │                          │                      │
        └──────────┬───────────────┘──────────────────────┘
                   │
                   ▼
          Feature Extraction
          & Normalization
                   │
                   ▼
        Preprocessing Pipeline
        (StandardScaler + OHE)
                   │
                   ▼
        Machine Learning Model
        (Random Forest Champion)
                   │
           ┌───────┴───────┐
           ▼               ▼
        NORMAL         MALICIOUS
                           │
                    ┌──────┴──────┐
                    ▼             ▼
              Risk Scoring   SOC Alert
           (CRITICAL/HIGH/  (Real-time
            MEDIUM/LOW)     Dashboard)
```

The system can therefore serve as a foundation for experimenting with machine-learning-based network intrusion detection, with real-time ingestion from public cybersecurity threat feeds.

---

## ⚠️ Limitations

This implementation has several practical limitations:

* Live data ingestion uses **public threat intelligence API feeds** (SANS ISC, abuse.ch, Emerging Threats) and TCP socket probes rather than raw packet capture (e.g., Scapy, Zeek, or SPAN port mirroring). Features are mapped from API telemetry to the UNSW-NB15 schema rather than extracted directly from packet headers.
* The single-packet interface is a **simulation** for manual header input, not a live packet-capture system.
* The model is trained specifically using the UNSW-NB15 dataset.
* Performance on real-world network traffic may differ from benchmark results, particularly since live API feed data is mapped to model features rather than natively captured.
* The system is a machine-learning prototype and should not be treated as a production enterprise IDS without additional validation.
* The current implementation performs binary classification (Normal / Malicious) rather than directly predicting individual attack categories.
* Live API feeds are rate-limited by their upstream providers; ingestion frequency should be configured accordingly.

---

## 🔮 Future Improvements

Possible future improvements include:

* Raw packet capture using Scapy or Zeek for direct PCAP-level feature extraction
* Multi-class attack classification (predicting specific attack categories such as Exploits, DoS, Reconnaissance, etc.)
* Explainable AI using SHAP to interpret individual predictions
* Database-backed threat history and persistent incident logging
* User authentication and role-based access control
* Continuous model retraining on newly collected live traffic
* Model drift monitoring to detect degradation over time
* Integration with SIEM platforms (e.g., Splunk, Elastic SIEM)
* Containerized deployment using Docker
* Webhook / Slack / email notifications for critical-severity detections
* GeoIP enrichment for live threat map visualization

---

## 📄 License

This project is released under the **MIT License**.

See the [LICENSE](LICENSE) file for details.
