import os
import json
import time
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

# Import live multi-source ingestion engine
from src.live_sources import (
    ingest_all_live_sources,
    predict_live_dataframe,
    get_source_summary_stats,
)

st.set_page_config(
    page_title="SecureNet SOC | AI-NIDS Live Detection Engine",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom SOC Dark Cyber Theme Styling
st.markdown(
    """
    <style>
    .soc-header {
        background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
        border: 1px solid #334155;
        border-radius: 12px;
        padding: 20px 24px;
        margin-bottom: 24px;
    }
    .soc-title {
        color: #38bdf8;
        font-size: 1.8rem;
        font-weight: 700;
        margin: 0;
        display: flex;
        align-items: center;
        gap: 10px;
    }
    .soc-subtitle {
        color: #94a3b8;
        font-size: 0.95rem;
        margin-top: 6px;
    }
    .feed-badge {
        display: inline-block;
        padding: 4px 10px;
        border-radius: 20px;
        font-size: 0.78rem;
        font-weight: 600;
        margin-right: 6px;
        margin-bottom: 4px;
    }
    .badge-sans { background-color: #1e3a8a; color: #bfdbfe; border: 1px solid #3b82f6; }
    .badge-feodo { background-color: #831843; color: #fbcfe8; border: 1px solid #ec4899; }
    .badge-et { background-color: #701a75; color: #f5d0fe; border: 1px solid #d946ef; }
    .badge-probe { background-color: #064e3b; color: #a7f3d0; border: 1px solid #10b981; }
    .alert-card {
        background: rgba(239, 68, 68, 0.12);
        border: 1px solid #ef4444;
        border-radius: 8px;
        padding: 12px 16px;
        margin-bottom: 12px;
    }
    </style>
    """,
    unsafe_allow_html=True,
)


# ==============================================================================
# 1. LOAD ARTIFACTS
# ==============================================================================
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


# ==============================================================================
# 2. SESSION STATE MANAGEMENT
# ==============================================================================
if "active_data" not in st.session_state:
    st.session_state.active_data = None
if "batch_metrics" not in st.session_state:
    st.session_state.batch_metrics = None
if "data_source_name" not in st.session_state:
    st.session_state.data_source_name = "Baseline Benchmark"
if "simulated_packets" not in st.session_state:
    st.session_state.simulated_packets = []
if "last_live_fetch" not in st.session_state:
    st.session_state.last_live_fetch = None


# ==============================================================================
# 3. SIDEBAR NAVIGATION & TELEMETRY STATUS
# ==============================================================================
st.sidebar.title("🛡️ SecureNet NIDS")
st.sidebar.caption("Enterprise AI Intrusion Detection & Live Telemetry")

selection = st.sidebar.radio(
    "Navigation",
    [
        "Overview Dashboard",
        "🌐 Live Multi-Source Stream (Public APIs)",
        "Visualizations & Metrics",
        "Threat Detection (Inference)",
    ],
)

st.sidebar.markdown("---")
st.sidebar.markdown(f"**Active Session Mode:**\n`{st.session_state.data_source_name}`")

if st.session_state.last_live_fetch:
    st.sidebar.caption(f"🕒 Last Live Sync: `{st.session_state.last_live_fetch}`")

if (
    st.session_state.active_data is not None
    or len(st.session_state.simulated_packets) > 0
):
    if st.sidebar.button("🔄 Reset Dashboard to Baseline", use_container_width=True):
        st.session_state.active_data = None
        st.session_state.batch_metrics = None
        st.session_state.simulated_packets = []
        st.session_state.data_source_name = "Baseline Benchmark"
        st.rerun()

st.sidebar.markdown("---")
st.sidebar.markdown("### 📡 Live Public Sources")
st.sidebar.markdown(
    """
    - 🌐 **SANS ISC Attacks**: Global honeypot sources
    - 🎯 **SANS ISC Ports**: Top targeted ports & scans
    - 🤖 **abuse.ch Feodo**: Botnet C2 servers
    - 🛡️ **Emerging Threats**: Active compromised hosts
    - ⚡ **Live Network Probe**: TCP latency probe (Cloudflare/Google)
    """
)

# Determine active dataframe (batch upload or live stream takes priority)
current_df = None
if st.session_state.active_data is not None:
    current_df = st.session_state.active_data
elif len(st.session_state.simulated_packets) > 0:
    current_df = pd.DataFrame(st.session_state.simulated_packets)


# ==============================================================================
# 4. OVERVIEW DASHBOARD
# ==============================================================================
if selection == "Overview Dashboard":
    st.markdown(
        """
        <div class="soc-header">
            <h2 class="soc-title">🛡️ AI-Powered Network Intrusion Detection Dashboard</h2>
            <div class="soc-subtitle">Real-time threat analytics, flow classification, and multi-source telemetry monitoring.</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

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
        r1_c2.metric("Intrusions Detected", f"{malicious_count:,}", delta=f"{intrusion_rate:.1f}% attack rate" if malicious_count > 0 else None, delta_color="inverse")
        r1_c3.metric("Normal Benign Flows", f"{normal_count:,}")
        r1_c4.metric("Attack Ratio", f"{intrusion_rate:.2f}%")

        st.markdown("---")

        # If data is from live multi-source feeds, show feed summary & quick actions
        if "Source_Feed" in current_df.columns:
            st.subheader("🌐 Public Source Feeds Breakdown")
            summary_stats = get_source_summary_stats(current_df)
            if not summary_stats.empty:
                st.dataframe(summary_stats, use_container_width=True, hide_index=True)

            # High severity intrusion alerts
            malicious_df = current_df[current_df["Classification"] == "MALICIOUS"]
            if not malicious_df.empty:
                st.subheader("🚨 Live Critical Intrusion Alerts")
                for _, row in malicious_df.head(4).iterrows():
                    source_feed = row.get("Source_Feed", "Telemetry Stream")
                    source_ip = row.get("Source_IP", "Unknown IP")
                    target_port = row.get("Target_Port", "N/A")
                    conf = row.get("Confidence", "N/A")
                    risk = row.get("Risk_Level", "HIGH")
                    meta = row.get("Feed_Metadata", "")

                    st.markdown(
                        f"""
                        <div class="alert-card">
                            <strong>🚨 [{risk} SEVERITY INTRUSION]</strong> From <code>{source_ip}</code> &rarr; Target Port: <code>{target_port}</code> |
                            Confidence: <strong>{conf}</strong> | Feed: <em>{source_feed}</em>
                            <br><small style="color: #cbd5e1;">Metadata: {meta}</small>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

        elif st.session_state.batch_metrics is not None:
            st.subheader("Evaluated Test Set Performance (Ground Truth Verified)")
            m = st.session_state.batch_metrics
            r2_c1, r2_c2, r2_c3, r2_c4 = st.columns(4)
            r2_c1.metric("Test Accuracy", f"{m['Accuracy']*100:.2f}%")
            r2_c2.metric("Test Recall", f"{m['Recall']*100:.2f}%")
            r2_c3.metric("Test Precision", f"{m['Precision']*100:.2f}%")
            r2_c4.metric("Test F1-Score", f"{m['F1-Score']*100:.2f}%")

        st.markdown("---")
        st.subheader("Inspection Log Table")
        
        # Priority columns for display
        priority_cols = ["Classification", "Confidence"]
        if "Risk_Level" in current_df.columns:
            priority_cols.append("Risk_Level")
        if "Source_Feed" in current_df.columns:
            priority_cols.append("Source_Feed")
        if "Source_IP" in current_df.columns:
            priority_cols.append("Source_IP")
        if "Target_Port" in current_df.columns:
            priority_cols.append("Target_Port")
        if "Feed_Metadata" in current_df.columns:
            priority_cols.append("Feed_Metadata")

        remaining_cols = [c for c in current_df.columns if c not in priority_cols]
        cols_to_show = priority_cols + remaining_cols
        st.dataframe(current_df[cols_to_show].head(25), use_container_width=True)

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

        st.info("💡 **Ready for Live Telemetry:** Go to the **'🌐 Live Multi-Source Stream (Public APIs)'** page to ingest live data from 4 public threat feeds and test the model in real time!")


# ==============================================================================
# 5. LIVE MULTI-SOURCE STREAM (PUBLIC APIS)
# ==============================================================================
elif selection == "🌐 Live Multi-Source Stream (Public APIs)":
    st.markdown(
        """
        <div class="soc-header">
            <h2 class="soc-title">🌐 Live Multi-Source Ingestion & Intrusion Prediction Engine</h2>
            <div class="soc-subtitle">Ingest live network security telemetry from 4 public cybersecurity APIs and real-time network probes, then classify threats in real-time.</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Public source overview badges
    st.markdown(
        """
        <span class="feed-badge badge-sans">📡 1. SANS ISC Attacks Feed (Live Attacking Sources)</span>
        <span class="feed-badge badge-sans">🎯 2. SANS ISC Target Ports (Live Port Scan Activity)</span>
        <span class="feed-badge badge-feodo">🤖 3. abuse.ch Feodo Tracker (Live Botnet C2 Stream)</span>
        <span class="feed-badge badge-et">🛡️ 4. Emerging Threats (Active Compromised Hosts)</span>
        <span class="feed-badge badge-probe">⚡ 5. Live Network Socket Probe (Public DNS/Web Telemetry)</span>
        """,
        unsafe_allow_html=True,
    )

    st.markdown("---")

    # Ingestion Control Bar
    col_c1, col_c2, col_c3 = st.columns([2, 1, 1])

    with col_c1:
        st.subheader("⚙️ Live Ingestion Configuration")
        f1 = st.checkbox("📡 Feed 1: SANS ISC Live Attacks Feed", value=True)
        f2 = st.checkbox("🎯 Feed 2: SANS ISC Target Ports & Telemetry", value=True)
        f3 = st.checkbox("🤖 Feed 3: abuse.ch Feodo Tracker (Botnet C2)", value=True)
        f4 = st.checkbox("🛡️ Feed 4: Proofpoint / Emerging Threats Compromised Hosts", value=True)
        f5 = st.checkbox("⚡ Feed 5: Live Real-Time Socket Probe (Cloudflare/Google)", value=True)

    with col_c2:
        st.subheader("🎚️ Feed Controls")
        sample_limit = st.slider(
            "Records Per Public Feed",
            min_value=3,
            max_value=30,
            value=8,
            help="Number of records to fetch from each active public source.",
        )
        auto_stream = st.toggle("⏱️ Continuous Auto-Stream", value=False)
        refresh_sec = 10
        if auto_stream:
            refresh_sec = st.select_slider(
                "Refresh Interval (seconds)",
                options=[5, 10, 15, 30],
                value=10,
            )
            st.caption(f"🔄 Auto-syncing every {refresh_sec}s...")

    with col_c3:
        st.subheader("🚀 Trigger Inference")
        fetch_clicked = st.button("🚀 Fetch & Predict Live Feeds Now", type="primary", use_container_width=True)
        st.caption("Fetches real-time records from selected public sources, normalizes into UNSW-NB15 features, and evaluates with the trained champion model.")

    with st.expander("🔗 Optional: Ingest from Custom Public/Private API Endpoint"):
        custom_url = st.text_input(
            "Custom API Endpoint (JSON / REST / Line-delimited IPs)",
            placeholder="e.g. https://api.threatintelligence.io/v1/feed or https://cinsscore.com/list/ci-badguys.txt",
        )

    # Ingestion Trigger Logic
    should_fetch = fetch_clicked or auto_stream

    if should_fetch:
        with st.spinner("Ingesting telemetry from public cybersecurity APIs & probing network sockets..."):
            df_live_raw = ingest_all_live_sources(
                limit_per_source=sample_limit,
                include_sans_attacks=f1,
                include_sans_ports=f2,
                include_feodo_c2=f3,
                include_emerging_threats=f4,
                include_live_probe=f5,
                custom_api_url=custom_url if custom_url else None,
            )

            if len(df_live_raw) > 0:
                df_live_pred = predict_live_dataframe(df_live_raw, model, preprocessor)
                st.session_state.active_data = df_live_pred
                st.session_state.data_source_name = f"Live Public Feeds ({len(df_live_pred)} records)"
                st.session_state.last_live_fetch = time.strftime("%H:%M:%S")
            else:
                st.warning("No records were retrieved from the selected sources. Please check internet connectivity or source selections.")

    # Display Current Live Telemetry Results
    if current_df is not None and "Source_Feed" in current_df.columns:
        total_p = len(current_df)
        mal_p = int((current_df["Classification"] == "MALICIOUS").sum())
        norm_p = total_p - mal_p
        att_rate = (mal_p / total_p) * 100 if total_p > 0 else 0

        st.markdown("---")
        st.subheader("📊 Live Threat Ingestion & Detection Metrics")

        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Live Packets Ingested", f"{total_p:,}")
        m2.metric("Malicious Intrusions", f"{mal_p:,}", delta=f"{att_rate:.1f}% Threat Ratio", delta_color="inverse")
        m3.metric("Normal Benign Flows", f"{norm_p:,}")
        m4.metric("Threat Rate", f"{att_rate:.2f}%")

        # Live Feed Breakdown Table
        st.markdown("### 📋 Multi-Source Ingestion & Prediction Breakdown")
        summary_table = get_source_summary_stats(current_df)
        st.dataframe(summary_table, use_container_width=True, hide_index=True)

        # Live Critical Intrusion Alerts Banner
        malicious_live = current_df[current_df["Classification"] == "MALICIOUS"]
        if not malicious_live.empty:
            st.markdown("### 🚨 Detected Live Threat Signals")
            cols_alerts = st.columns(min(3, len(malicious_live)))
            for idx, (_, row) in enumerate(malicious_live.head(3).iterrows()):
                with cols_alerts[idx % 3]:
                    st.markdown(
                        f"""
                        <div class="alert-card">
                            <strong style="color: #ef4444;">🚨 [{row.get('Risk_Level', 'HIGH')} THREAT]</strong><br>
                            <strong>IP:</strong> <code>{row.get('Source_IP', 'N/A')}</code><br>
                            <strong>Target Port:</strong> <code>{row.get('Target_Port', 'N/A')}</code><br>
                            <strong>Confidence:</strong> <strong>{row.get('Confidence', 'N/A')}</strong><br>
                            <strong>Source:</strong> <em>{row.get('Source_Feed', 'N/A')}</em><br>
                            <small>{row.get('Feed_Metadata', '')}</small>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

        # Interactive Filtering & Full Live Inspection Log
        st.markdown("---")
        st.subheader("🔍 Live Inspection Log Table")

        col_f1, col_f2, col_f3 = st.columns(3)
        with col_f1:
            feed_filter = st.selectbox(
                "Filter by Source Feed",
                ["All Feeds"] + sorted(current_df["Source_Feed"].unique().tolist()),
            )
        with col_f2:
            class_filter = st.selectbox(
                "Filter by Classification",
                ["All", "MALICIOUS Only", "NORMAL Only"],
            )
        with col_f3:
            search_query = st.text_input("Search IP / Port / Metadata", "")

        filtered_df = current_df.copy()
        if feed_filter != "All Feeds":
            filtered_df = filtered_df[filtered_df["Source_Feed"] == feed_filter]
        if class_filter == "MALICIOUS Only":
            filtered_df = filtered_df[filtered_df["Classification"] == "MALICIOUS"]
        elif class_filter == "NORMAL Only":
            filtered_df = filtered_df[filtered_df["Classification"] == "NORMAL"]
        if search_query.strip():
            sq = search_query.lower()
            filtered_df = filtered_df[
                filtered_df["Source_IP"].astype(str).str.lower().str.contains(sq)
                | filtered_df["Target_Port"].astype(str).str.contains(sq)
                | filtered_df["Feed_Metadata"].astype(str).str.lower().str.contains(sq)
            ]

        display_cols = [
            "Classification",
            "Confidence",
            "Risk_Level",
            "Source_Feed",
            "Source_IP",
            "Target_Port",
            "Timestamp",
            "Feed_Metadata",
            "proto",
            "service",
            "dur",
            "rate",
            "sbytes",
            "dbytes",
            "sttl",
        ]
        valid_display_cols = [c for c in display_cols if c in filtered_df.columns]
        st.dataframe(filtered_df[valid_display_cols], use_container_width=True)

        # Quick CSV Download for Incident Response Logs
        csv_data = filtered_df.to_csv(index=False).encode("utf-8")
        st.download_button(
            "📥 Download Live Threat Telemetry Report (CSV)",
            data=csv_data,
            file_name=f"live_threat_feed_{time.strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv",
        )

        # Auto-refresh loop handling
        if auto_stream:
            time.sleep(refresh_sec)
            st.rerun()

    else:
        st.info("👆 Click **'🚀 Fetch & Predict Live Feeds Now'** above to fetch live data from the 4 public APIs and observe live intrusion detection!")


# ==============================================================================
# 6. VISUALIZATIONS & METRICS
# ==============================================================================
elif selection == "Visualizations & Metrics":
    st.markdown(
        """
        <div class="soc-header">
            <h2 class="soc-title">📊 Security Analytics & Visualizations</h2>
            <div class="soc-subtitle">Distribution analysis, multi-source telemetry comparisons, and model confusion matrices.</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

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
            for p in ax_dist.patches:
                height = p.get_height()
                if not np.isnan(height) and height > 0:
                    ax_dist.annotate(
                        f"{int(height)}",
                        (p.get_x() + p.get_width() / 2.0, height / 2.0),
                        ha="center",
                        va="center",
                        color="white",
                        fontweight="bold",
                    )
            plt.tight_layout()
            st.pyplot(fig_dist)
        else:
            st.caption("Training Set Class Distribution (Baseline)")
            eda_path = "static/eda_attack_distribution.png"
            if os.path.exists(eda_path):
                st.image(eda_path, use_container_width=True)

    with col2:
        if current_df is not None and "Source_Feed" in current_df.columns:
            st.subheader("Intrusions Detected per Public Source Feed")
            st.caption(f"Threat breakdown across public cyber telemetry streams")
            fig_src, ax_src = plt.subplots(figsize=(6, 4))
            sns.countplot(
                data=current_df,
                y="Source_Feed",
                hue="Classification",
                palette={"NORMAL": "#10b981", "MALICIOUS": "#ef4444"},
                ax=ax_src,
            )
            ax_src.set_xlabel("Packet Count")
            ax_src.set_ylabel("")
            plt.tight_layout()
            st.pyplot(fig_src)
        else:
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
                    "Live packet feeds without ground-truth 'label' columns display operational detection distributions rather than confusion matrices."
                )
            else:
                st.caption("Baseline Confusion Matrix on Model Test Partition")
                cm_path = "static/confusion_matrix.png"
                if os.path.exists(cm_path):
                    st.image(cm_path, use_container_width=True)


# ==============================================================================
# 7. THREAT DETECTION (INFERENCE)
# ==============================================================================
elif selection == "Threat Detection (Inference)":
    st.markdown(
        """
        <div class="soc-header">
            <h2 class="soc-title">🚨 Threat Detection & Packet Inspection Hub</h2>
            <div class="soc-subtitle">Inspect live multi-source streams, upload CSV network flow captures, or simulate custom packet headers.</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    tab_live, tab_batch, tab_single = st.tabs(
        [
            "🌐 Live Multi-Source Public Feeds",
            "📁 Batch CSV Inspection",
            "🎯 Single Packet Simulation",
        ]
    )

    # --------------------------------------------------------------------------
    # Tab 1: Live Multi-Source Feeds (Public APIs)
    # --------------------------------------------------------------------------
    with tab_live:
        st.subheader("🌐 Ingest & Predict Live Public Threat Telemetry")
        st.markdown(
            "Quickly fetch live records from SANS ISC Attacks, SANS ISC Top Ports, abuse.ch Feodo Tracker, and Proofpoint Emerging Threats."
        )

        c1, c2 = st.columns([3, 1])
        with c1:
            q_limit = st.slider("Records per Source Feed", 3, 25, 6, key="quick_limit")
        with c2:
            st.write("")
            st.write("")
            run_quick = st.button("🚀 Ingest & Classify Now", type="primary", use_container_width=True)

        if run_quick:
            with st.spinner("Fetching live public feeds and predicting..."):
                raw_live = ingest_all_live_sources(limit_per_source=q_limit)
                pred_live = predict_live_dataframe(raw_live, model, preprocessor)
                st.session_state.active_data = pred_live
                st.session_state.data_source_name = f"Live Public Feeds ({len(pred_live)} records)"
                st.session_state.last_live_fetch = time.strftime("%H:%M:%S")
                st.success(f"Successfully ingested and classified {len(pred_live)} live records across all active sources!")
                st.rerun()

        if current_df is not None and "Source_Feed" in current_df.columns:
            st.markdown("### Latest Live Telemetry Summary")
            st.dataframe(get_source_summary_stats(current_df), use_container_width=True, hide_index=True)

    # --------------------------------------------------------------------------
    # Tab 2: Batch CSV Inspection
    # --------------------------------------------------------------------------
    with tab_batch:
        st.subheader("Batch Packet Analysis from CSV")
        uploaded_file = st.file_uploader(
            "Upload Network Traffic Capture (CSV)", type=["csv"], key="batch_uploader"
        )

        if uploaded_file is not None:
            raw_input_df = pd.read_csv(uploaded_file)
            st.write(
                f"Loaded **{len(raw_input_df):,}** records from `{uploaded_file.name}`."
            )

            if st.button("Run Intrusion Detection & Update Dashboard", type="primary", key="batch_run_btn"):
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
                    feature_names = preprocessor.get_feature_names_out()
                    X_df = pd.DataFrame(transformed, columns=feature_names)
                    predictions = model.predict(X_df)
                    probs = (
                        model.predict_proba(X_df)[:, 1]
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

                    st.success("Batch analysis complete! Dashboard updated.")
                    st.rerun()

    # --------------------------------------------------------------------------
    # Tab 3: Single Packet Simulation
    # --------------------------------------------------------------------------
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
                "Service (service)", ["unknown", "http", "ftp", "smtp", "dns", "ssl", "ssh"]
            )
            state = st.selectbox("State (state)", ["INT", "FIN", "CON", "REQ", "RST"])
            rate = st.number_input("Rate", min_value=0.0, value=952.38)
            sttl = st.number_input("Source TTL (sttl)", min_value=0, value=254)

        if st.button("Inspect Packet & Log to Dashboard", type="primary", key="single_inspect_btn"):
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
            feature_names = preprocessor.get_feature_names_out()
            X_df = pd.DataFrame(transformed_sample, columns=feature_names)
            prediction = model.predict(X_df)[0]
            probability = (
                model.predict_proba(X_df)[0]
                if hasattr(model, "predict_proba")
                else [0.5, 0.5]
            )

            verdict = "MALICIOUS" if prediction == 1 else "NORMAL"
            conf_val = probability[1] if prediction == 1 else probability[0]

            logged_packet = input_data.copy()
            logged_packet["Classification"] = verdict
            logged_packet["Confidence"] = f"{conf_val*100:.1f}%"
            logged_packet["Source_Feed"] = "Simulated Header"
            logged_packet["Source_IP"] = "Simulated_Packet"
            logged_packet["Target_Port"] = 80
            st.session_state.simulated_packets.insert(0, logged_packet)

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
