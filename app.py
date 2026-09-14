import os
import json
import joblib
import numpy as np
import pandas as pd
import streamlit as st
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)

st.set_page_config(
    page_title="SecureNet Corp | AI-NIDS Dashboard", page_icon="🛡️", layout="wide"
)


# 1. LOAD ARTIFACTS
@st.cache_resource
def load_artifacts():
    model = joblib.load("models/best_model.joblib")
    preprocessor = joblib.load("data/processed/preprocessor.joblib")
    return model, preprocessor


@st.cache_data
def load_metrics():
    metrics_path = "models/metrics_summary.json"
    if os.path.exists(metrics_path):
        with open(metrics_path, "r") as f:
            return json.load(f)
    return {}


try:
    model, preprocessor = load_artifacts()
    baseline_metrics = load_metrics()
except Exception as e:
    st.error(f"Error loading artifacts: {e}")
    st.stop()

# 2. SESSION STATE MANAGEMENT
if "active_data" not in st.session_state:
    st.session_state.active_data = None
if "batch_metrics" not in st.session_state:
    st.session_state.batch_metrics = None
if "data_source_name" not in st.session_state:
    st.session_state.data_source_name = "Baseline Benchmark"
if "simulated_packets" not in st.session_state:
    st.session_state.simulated_packets = []

# 3. SIDEBAR NAVIGATION
st.sidebar.title("🛡️ SecureNet NIDS")
st.sidebar.caption("Intelligent Intrusion Detection System")
selection = st.sidebar.radio(
    "Navigation",
    ["Overview Dashboard", "Visualizations & Metrics", "Threat Detection (Inference)"],
)

st.sidebar.markdown("---")
st.sidebar.markdown(f"**Active Session Mode:**\n`{st.session_state.data_source_name}`")

if (
    st.session_state.active_data is not None
    or len(st.session_state.simulated_packets) > 0
):
    if st.sidebar.button("Reset Dashboard to Baseline", use_container_width=True):
        st.session_state.active_data = None
        st.session_state.batch_metrics = None
        st.session_state.simulated_packets = []
        st.session_state.data_source_name = "Baseline Benchmark"
        st.rerun()

# Determine active dataframe (batch upload takes priority over simulated packet buffer)
current_df = None
if st.session_state.active_data is not None:
    current_df = st.session_state.active_data
elif len(st.session_state.simulated_packets) > 0:
    current_df = pd.DataFrame(st.session_state.simulated_packets)

# ==============================================================================
# 4. OVERVIEW DASHBOARD
# ==============================================================================
if selection == "Overview Dashboard":
    st.title("🛡️ AI-Powered Network Intrusion Detection System")

    if current_df is not None:
        total_packets = len(current_df)
        malicious_count = int((current_df["Classification"] == "MALICIOUS").sum())
        normal_count = total_packets - malicious_count
        intrusion_rate = (
            (malicious_count / total_packets) * 100 if total_packets > 0 else 0
        )

        st.success(
            f"**Active Telemetry Feed:** Displaying live data from `{st.session_state.data_source_name}`"
        )

        r1_c1, r1_c2, r1_c3, r1_c4 = st.columns(4)
        r1_c1.metric("Packets Ingested", f"{total_packets:,}")
        r1_c2.metric("Intrusions Detected", f"{malicious_count:,}")
        r1_c3.metric("Normal Flows", f"{normal_count:,}")
        r1_c4.metric("Attack Ratio", f"{intrusion_rate:.2f}%")

        st.markdown("---")

        if st.session_state.batch_metrics is not None:
            st.subheader("Evaluated Test Set Performance (Ground Truth Verified)")
            m = st.session_state.batch_metrics
            r2_c1, r2_c2, r2_c3, r2_c4 = st.columns(4)
            r2_c1.metric("Test Accuracy", f"{m['Accuracy']*100:.2f}%")
            r2_c2.metric("Test Recall", f"{m['Recall']*100:.2f}%")
            r2_c3.metric("Test Precision", f"{m['Precision']*100:.2f}%")
            r2_c4.metric("Test F1-Score", f"{m['F1-Score']*100:.2f}%")
        else:
            st.info(
                "Live packet feed without ground-truth labels. Displaying operational detection counts."
            )

        st.markdown("---")
        st.subheader("Inspection Log Table")
        cols_to_show = ["Classification", "Confidence"] + [
            c for c in current_df.columns if c not in ["Classification", "Confidence"]
        ]
        st.dataframe(current_df[cols_to_show].head(15), use_container_width=True)

    else:
        st.markdown(
            "Displaying initial model benchmark performance (**UNSW-NB15 Test Set Evaluation**)."
        )
        if baseline_metrics:
            st.subheader("Baseline Model Performance")
            best_model_name = list(baseline_metrics.keys())[-1]
            stats = baseline_metrics.get(
                best_model_name, list(baseline_metrics.values())[-1]
            )

            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Model Architecture", best_model_name)
            c2.metric("Benchmark Accuracy", f"{stats['Accuracy']*100:.2f}%")
            c3.metric("Benchmark Recall", f"{stats['Recall']*100:.2f}%")
            c4.metric("Benchmark Precision", f"{stats['Precision']*100:.2f}%")

            st.markdown("---")
            st.subheader("Algorithm Comparison Matrix")
            st.dataframe(
                pd.DataFrame(baseline_metrics)
                .T.style.format("{:.4f}")
                .highlight_max(axis=0, color="#d4edda"),
                use_container_width=True,
            )

# ==============================================================================
# 5. VISUALIZATIONS & METRICS
# ==============================================================================
elif selection == "Visualizations & Metrics":
    st.title("📊 Security Analytics & Visualizations")
    col1, col2 = st.columns(2)

    with col1:
        st.subheader("Traffic Class Distribution")
        if current_df is not None:
            st.caption(f"Active Session: `{st.session_state.data_source_name}`")
            fig_dist, ax_dist = plt.subplots(figsize=(6, 4))
            sns.countplot(
                data=current_df,
                x="Classification",
                order=["NORMAL", "MALICIOUS"],
                palette={"NORMAL": "#10b981", "MALICIOUS": "#ef4444"},
                ax=ax_dist,
            )
            ax_dist.set_ylabel("Packet Count")
            plt.tight_layout()
            st.pyplot(fig_dist)
        else:
            st.caption("Training Set Class Distribution (Baseline)")
            eda_path = "static/eda_attack_distribution.png"
            if os.path.exists(eda_path):
                st.image(eda_path, use_container_width=True)

    with col2:
        st.subheader("Confusion Matrix")
        if st.session_state.batch_metrics is not None:
            st.caption(
                f"Calculated from ground-truth in `{st.session_state.data_source_name}`"
            )
            cm = st.session_state.batch_metrics["Confusion_Matrix"]
            fig_cm, ax_cm = plt.subplots(figsize=(6, 4))
            sns.heatmap(
                cm,
                annot=True,
                fmt="d",
                cmap="Blues",
                xticklabels=["Normal (0)", "Attack (1)"],
                yticklabels=["Normal (0)", "Attack (1)"],
                ax=ax_cm,
            )
            ax_cm.set_ylabel("Actual Label")
            ax_cm.set_xlabel("Predicted Label")
            plt.tight_layout()
            st.pyplot(fig_cm)
        elif current_df is not None:
            st.info(
                "Simulated/unlabelled packets do not have ground-truth 'label' columns, so a confusion matrix cannot be plotted."
            )
        else:
            st.caption("Baseline Confusion Matrix on Model Test Partition")
            cm_path = "static/confusion_matrix.png"
            if os.path.exists(cm_path):
                st.image(cm_path, use_container_width=True)

# ==============================================================================
# 6. THREAT DETECTION (INFERENCE)
# ==============================================================================
elif selection == "Threat Detection (Inference)":
    st.title("🚨 Live Threat Detection & Packet Inspection")
    tab_batch, tab_single = st.tabs(
        ["Batch CSV Inspection", "Single Packet Simulation"]
    )

    with tab_batch:
        st.subheader("Batch Packet Analysis")
        uploaded_file = st.file_uploader(
            "Upload Network Traffic Capture (CSV)", type=["csv"]
        )

        if uploaded_file is not None:
            raw_input_df = pd.read_csv(uploaded_file)
            st.write(
                f"Loaded **{len(raw_input_df):,}** records from `{uploaded_file.name}`."
            )

            if st.button("Run Intrusion Detection & Update Dashboard", type="primary"):
                with st.spinner("Analyzing traffic patterns..."):
                    data = raw_input_df.copy()
                    actual_labels = (
                        data["label"].values if "label" in data.columns else None
                    )

                    data.drop(
                        columns=["id", "label", "attack_cat"],
                        inplace=True,
                        errors="ignore",
                    )
                    for col in ["proto", "service", "state"]:
                        if col in data.columns:
                            data[col] = (
                                data[col].replace("-", "unknown").fillna("unknown")
                            )

                    transformed = preprocessor.transform(data)
                    predictions = model.predict(transformed)
                    probs = (
                        model.predict_proba(transformed)[:, 1]
                        if hasattr(model, "predict_proba")
                        else [None] * len(predictions)
                    )

                    raw_input_df["Classification"] = np.where(
                        predictions == 1, "MALICIOUS", "NORMAL"
                    )
                    raw_input_df["Confidence"] = [
                        f"{p*100:.1f}%" if p is not None else "N/A" for p in probs
                    ]

                    st.session_state.active_data = raw_input_df
                    st.session_state.data_source_name = uploaded_file.name

                    if actual_labels is not None:
                        st.session_state.batch_metrics = {
                            "Accuracy": float(
                                accuracy_score(actual_labels, predictions)
                            ),
                            "Precision": float(
                                precision_score(
                                    actual_labels, predictions, zero_division=0
                                )
                            ),
                            "Recall": float(
                                recall_score(
                                    actual_labels, predictions, zero_division=0
                                )
                            ),
                            "F1-Score": float(
                                f1_score(actual_labels, predictions, zero_division=0)
                            ),
                            "Confusion_Matrix": confusion_matrix(
                                actual_labels, predictions
                            ),
                        }
                    else:
                        st.session_state.batch_metrics = None

                    st.rerun()

    with tab_single:
        st.subheader("Simulated Packet Header Input")
        col_a, col_b = st.columns(2)
        with col_a:
            dur = st.number_input(
                "Duration (dur)", min_value=0.0, value=0.00105, format="%.5f"
            )
            spkts = st.number_input("Source Packets (spkts)", min_value=1, value=2)
            dpkts = st.number_input("Destination Packets (dpkts)", min_value=0, value=0)
            sbytes = st.number_input("Source Bytes (sbytes)", min_value=0, value=146)
            dbytes = st.number_input("Destination Bytes (dbytes)", min_value=0, value=0)

        with col_b:
            proto = st.selectbox(
                "Protocol (proto)", ["tcp", "udp", "arp", "ospf", "unknown"]
            )
            service = st.selectbox(
                "Service (service)", ["unknown", "http", "ftp", "smtp", "dns"]
            )
            state = st.selectbox("State (state)", ["INT", "FIN", "CON", "REQ"])
            rate = st.number_input("Rate", min_value=0.0, value=952.38)
            sttl = st.number_input("Source TTL (sttl)", min_value=0, value=254)

        if st.button("Inspect Packet & Log to Dashboard", type="primary"):
            input_data = {
                "dur": dur,
                "proto": proto,
                "service": service,
                "state": state,
                "spkts": spkts,
                "dpkts": dpkts,
                "sbytes": sbytes,
                "dbytes": dbytes,
                "rate": rate,
                "sttl": sttl,
                "dttl": 0,
                "sload": 553554.5,
                "dload": 0.0,
                "sloss": 0,
                "dloss": 0,
                "sinpkt": 0.001,
                "dinpkt": 0.0,
                "sjit": 0.0,
                "djit": 0.0,
                "swin": 0,
                "stcpb": 0,
                "dtcpb": 0,
                "dwin": 0,
                "tcprtt": 0.0,
                "synack": 0.0,
                "ackdat": 0.0,
                "smean": 73,
                "dmean": 0,
                "trans_depth": 0,
                "response_body_len": 0,
                "ct_srv_src": 1,
                "ct_state_ttl": 2,
                "ct_dst_ltm": 1,
                "ct_src_dport_ltm": 1,
                "ct_dst_sport_ltm": 1,
                "ct_dst_src_ltm": 1,
                "is_ftp_login": 0,
                "ct_ftp_cmd": 0,
                "ct_flw_http_mthd": 0,
                "ct_src_ltm": 1,
                "ct_srv_dst": 1,
                "is_sm_ips_ports": 0,
            }
            sample_df = pd.DataFrame([input_data])
            transformed_sample = preprocessor.transform(sample_df)
            prediction = model.predict(transformed_sample)[0]
            probability = (
                model.predict_proba(transformed_sample)[0]
                if hasattr(model, "predict_proba")
                else [0.5, 0.5]
            )

            verdict = "MALICIOUS" if prediction == 1 else "NORMAL"
            conf_val = probability[1] if prediction == 1 else probability[0]

            # Log packet to session state so dashboard reflects it
            logged_packet = input_data.copy()
            logged_packet["Classification"] = verdict
            logged_packet["Confidence"] = f"{conf_val*100:.1f}%"
            st.session_state.simulated_packets.insert(0, logged_packet)

            # Switch view source if no batch data is active
            if st.session_state.active_data is None:
                st.session_state.data_source_name = "Live Simulated Stream"

            if prediction == 1:
                st.error(
                    f"🚨 INTRUSION DETECTED (Confidence: {conf_val*100:.2f}%) — Logged to Dashboard!"
                )
            else:
                st.success(
                    f"✅ NORMAL TRAFFIC (Confidence: {conf_val*100:.2f}%) — Logged to Dashboard!"
                )
