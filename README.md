# Enterprise AI-Powered Network Intrusion Detection System (NIDS)

An end-to-end machine learning engineering framework designed to detect, classify, and mitigate zero-day perimeter intrusions and anomalous network telemetry in real time. Built upon the comprehensive **UNSW-NB15** network benchmark, this system integrates modular data engineering pipelines, multi-model evaluation focusing on high-recall security boundaries, and an interactive Security Operations Center (SOC) dashboard.

---

## System Architecture

```text
Raw Network Packets / Ingested PCAP Streams
                    │
                    ▼
     [ Data Sanitization & Imputation ] ──> Handles protocol tokens & missing values
                    │
                    ▼
    [ Transformer Pipeline (ColumnTransformer) ]
       ├── Robust Standard Scaler (Continuous Header Metrics)
       └── One-Hot Encoding (Protocol, Service, State Flags)
                    │
                    ▼
         [ Multi-Model Benchmarking ]
       ├── Logistic Regression (Baseline Linear Boundary)
       ├── Decision Tree Classifier (Orthogonal Feature Splitting)
       └── Random Forest Ensemble (Variance Reduction & Feature Importance)
                    │
                    ▼
    [ Champion Serialization & Threat Engine ]
       ├── best_model.joblib (Optimized for Attack Recall)
       └── preprocessor.joblib (Stateful Input Transformer)
                    │
                    ▼
   [ Real-Time Streamlit SOC Dashboard (app.py) ]
       ├── Dynamic Batch Ingestion & Real-Time Threat Scoring
       ├── Single-Packet Simulation & Header Anomaly Inspection
       └── Dynamic Confusion Matrix & Ingestion Ratio Telemetry
```

---

## Key Features

- **Strict Train-Test Isolation:** Feature transformation pipelines are fitted strictly against the training distribution, preventing data leakage across test evaluations.
- **Recall-Optimized Objective:** Prioritizes attack recall over generic accuracy to minimize **False Negatives** (unmitigated intrusions bypassing perimeter defenses).
- **Dynamic Streamlit SOC Console:** Automatically recalculates live accuracy, attack ratio, and confusion matrices when processing newly ingested packet logs.
- **Modular Pipeline Architecture:** Provides production-grade separation between research notebooks (`notebooks/`) and headless automation modules (`src/`).

---

## Directory Organization

```text
network-intrusion-detection-unsw-nb15-ml/
│
├── notebooks/
│   ├── 01_data_preprocessing_and_eda.ipynb    # Data exploration & feature engineering
│   └── 02_model_training_and_evaluation.ipynb  # Multi-algorithm tuning & evaluation
│
├── src/
│   ├── __init__.py               # Python package initialization
│   ├── preprocess.py             # Reusable ETL & transformation script
│   ├── train.py                  # Headless training & model selection script
│   └── evaluate.py               # Test-set benchmarking & matrix generation
│
├── static/
│   ├── confusion_matrix.png      # Baseline test set confusion matrix
│   └── eda_attack_distribution.png # Attack category frequency distribution
│
├── app.py                        # Real-time Streamlit SOC monitoring interface
├── requirements.txt              # Pinned, deterministic dependency manifest
└── README.md
```

---

## Dataset Description: UNSW-NB15

The **UNSW-NB15** dataset was created using an IXIA PerfectStorm tool in the Cyber Range Lab of the Australian Centre for Cyber Security (ACCS) to generate a hybrid of real modern normal activities and contemporary synthetic attack behaviors.

- **Total Records benchmarked:** 175,341 training flows and 82,332 testing flows.
- **Target Classes:** Binary classification (`0` for Benign traffic, `1` for Malicious intrusion).
- **Attack Vectors Covered:** Fuzzers, Analysis, Backdoors, DoS, Exploits, Generic, Reconnaissance, Shellcode, and Worms.
- **Key Header Features:** Continuous metrics (`dur`, `sbytes`, `dbytes`, `rate`, `sttl`) and categorical connection markers (`proto`, `service`, `state`).

---

## Installation & Environment Setup

### 1. Clone the Repository

```bash
git clone https://github.com/<your-username>/network-intrusion-detection-unsw-nb15-ml.git
cd network-intrusion-detection-unsw-nb15-ml
```

### 2. Configure Virtual Environment

```bash
# Windows:
python -m venv venv
.\venv\Scripts\activate

# Linux / macOS:
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

---

## Execution Workflow

### Option A: Automated Headless Pipeline (Recommended)

Run the automated source modules directly from the repository root:

```bash
# 1. Preprocess raw data, scale features, and serialize transformer
python src/preprocess.py

# 2. Train candidate models and select the champion architecture
python src/train.py

# 3. Evaluate on unseen test partitions and export static metrics
python src/evaluate.py
```

### Option B: Interactive Research Notebooks

For step-by-step exploratory inspection and visual analysis:

```bash
jupyter notebook notebooks/01_data_preprocessing_and_eda.ipynb
jupyter notebook notebooks/02_model_training_and_evaluation.ipynb
```

### Option C: Launch the Interactive SOC Dashboard

Deploy the local web-based intrusion detection interface:

```bash
streamlit run app.py
```

---

## Performance & Security Evaluation

The classification models were benchmarked across standard performance dimensions on the unseen test set ($N = 82,332$). In an enterprise NIDS deployment, **Attack Recall** is prioritized to reduce critical blind spots:

$$
\text{Recall} = \frac{\text{True Positives}}{\text{True Positives} + \text{False Negatives}}
$$

| Model Architecture               |  Accuracy  | Attack Recall | Precision  |  F1-Score  |
| :------------------------------- | :--------: | :-----------: | :--------: | :--------: |
| **Logistic Regression**          |   ~81.2%   |    ~78.4%     |   ~84.1%   |   ~81.1%   |
| **Decision Tree (max_depth=12)** |   ~86.8%   |    ~88.2%     |   ~87.4%   |   ~87.8%   |
| **Random Forest (Best)**         | **~90.3%** |  **~92.1%**   | **~89.8%** | **~90.9%** |

### Security Implications

- **Low False Negatives:** The Random Forest champion minimizes instances where malicious packets slip into the internal network as legitimate traffic.
- **Controlled False Positives:** Precision remains near 90%, preventing Security Operations Center (SOC) alert fatigue while maintaining high perimeter coverage.

---

## Dashboard Walkthrough (`app.py`)

- **Overview Dashboard:** Provides continuous tracking of total ingested packet volume, classified threats, normal flows, and real-time detection ratios.
- **Visualizations & Metrics:** Renders dynamic confusion matrices and traffic distributions that adapt directly to uploaded packet logs.
- **Threat Detection Engine:**
  - **Batch Packet Analysis:** Accepts arbitrary network log CSVs, applies the saved preprocessor pipeline, and exports timestamped, annotated CSV threat logs.
  - **Single Packet Simulation:** Allows security operators to manually input connection parameters (`dur`, `proto`, `service`, `sttl`, `spkts`) to inspect inline classification confidence.

---

## License & Citations

- **Dataset:** UNSW-NB15 provided by the Cyber Range Lab of the Australian Centre for Cyber Security (ACCS).
- **License:** Distributed under the MIT License. See `LICENSE` for further details.
