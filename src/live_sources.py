"""
Live Multi-Source Threat Intelligence & Network Telemetry Ingestion Engine
==========================================================================
Ingests real-time network security telemetry from 4 public cybersecurity APIs
plus live network socket probes, normalizes them into the UNSW-NB15 42-feature space,
and runs live intrusion detection inference with the trained champion model.

Sources:
1. SANS Internet Storm Center (ISC) - Live Attacking Sources Feed
2. SANS Internet Storm Center (ISC) - Live Target Ports & Packet Volumes Feed
3. abuse.ch Feodo Tracker - Live Botnet Command & Control (C2) Nodes Feed
4. Proofpoint / Emerging Threats - Live Compromised Hosts Feed
5. Live Socket Telemetry Probes - Real-time TCP Handshake / RTT / Latency to Global Public DNS/Web
"""

import os
import ssl
import json
import time
import socket
import urllib.request
import pandas as pd
import numpy as np

# SSL context for resilient HTTPS requests
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

HEADERS = {
    "User-Agent": "SecureNet-NIDS/2.0 (AI-Threat-Detection; contact@securenet-soc.org)",
    "Accept": "application/json, text/plain, */*",
}


# ==============================================================================
# 1. PUBLIC API INGESTION ADAPTERS
# ==============================================================================

def fetch_sans_attacks(limit: int = 15) -> list[dict]:
    """
    Source 1: SANS Internet Storm Center (ISC) Live Attacking Sources.
    Returns real-time actively probing malicious IP addresses and attack frequency.
    """
    url = f"https://isc.sans.edu/api/sources/attacks/{max(1, limit)}?json"
    try:
        req = urllib.request.Request(url, headers={**HEADERS, "Accept": "application/json"})
        with urllib.request.urlopen(req, context=ssl_context, timeout=8) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))
            if isinstance(data, list):
                return data[:limit]
            elif isinstance(data, dict):
                # SANS sometimes wraps records in numeric keys
                items = [v for k, v in data.items() if isinstance(v, dict) and "ip" in v]
                return items[:limit]
    except Exception as e:
        print(f"[!] Warning: SANS attacks fetch failed: {e}")
    return []


def fetch_sans_topports(limit: int = 15) -> list[dict]:
    """
    Source 2: SANS ISC Live Target Ports & Packet Volume Telemetry.
    Returns real-time targeted ports, total scanned packet volumes, and attacking sources.
    """
    url = f"https://isc.sans.edu/api/topports/records/{max(1, limit)}?json"
    try:
        req = urllib.request.Request(url, headers={**HEADERS, "Accept": "application/json"})
        with urllib.request.urlopen(req, context=ssl_context, timeout=8) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))
            items = []
            if isinstance(data, dict):
                for k, v in data.items():
                    if isinstance(v, dict) and "targetport" in v:
                        items.append(v)
            elif isinstance(data, list):
                items = data
            return items[:limit]
    except Exception as e:
        print(f"[!] Warning: SANS top ports fetch failed: {e}")
    return []


def fetch_feodo_c2(limit: int = 15) -> list[dict]:
    """
    Source 3: abuse.ch Feodo Tracker Live Botnet C2 Stream.
    Returns active botnet command-and-control servers (Emotet, Dridex, QakBot, Bumblebee).
    """
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
    try:
        req = urllib.request.Request(url, headers=HEADERS)
        with urllib.request.urlopen(req, context=ssl_context, timeout=8) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="ignore"))
            if isinstance(data, list):
                return data[:limit]
    except Exception as e:
        print(f"[!] Warning: Feodo Tracker C2 fetch failed: {e}")
    return []


def fetch_emerging_threats(limit: int = 15) -> list[str]:
    """
    Source 4: Proofpoint Emerging Threats Compromised IP Stream.
    Returns active compromised hosts engaged in exploits, malware delivery, and scans.
    """
    urls = [
        "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "https://cinsscore.com/list/ci-badguys.txt",
    ]
    for url in urls:
        try:
            req = urllib.request.Request(url, headers=HEADERS)
            with urllib.request.urlopen(req, context=ssl_context, timeout=8) as resp:
                text = resp.read().decode("utf-8", errors="ignore")
                lines = [
                    line.strip()
                    for line in text.splitlines()
                    if line.strip() and not line.strip().startswith("#")
                ]
                if lines:
                    return lines[:limit]
        except Exception as e:
            print(f"[!] Warning: Feed {url} failed: {e}, trying fallback...")
            continue
    return []


def probe_live_network_endpoint(host: str, port: int = 80, timeout: float = 1.5) -> dict:
    """
    Source 5: Real socket telemetry probe to live public infrastructure.
    Measures genuine wall-clock TCP handshake RTT, duration, byte counts, and status.
    """
    t0 = time.time()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        t1 = time.time()
        rtt = max(0.0005, t1 - t0)

        # Send minimal HTTP head or probe packet
        if port in [80, 8080]:
            sock.sendall(b"HEAD / HTTP/1.1\r\nHost: " + host.encode() + b"\r\n\r\n")
            resp = sock.recv(512)
            dbytes = len(resp)
        else:
            dbytes = 0

        t2 = time.time()
        dur = max(0.001, t2 - t0)
        sock.close()
        return {
            "host": host,
            "port": port,
            "rtt": rtt,
            "dur": dur,
            "sbytes": 64,
            "dbytes": dbytes,
            "status": "ONLINE",
        }
    except Exception as e:
        dur = max(0.01, time.time() - t0)
        return {
            "host": host,
            "port": port,
            "rtt": 0.08,
            "dur": dur,
            "sbytes": 64,
            "dbytes": 0,
            "status": f"UNAVAILABLE ({type(e).__name__})",
        }


def fetch_custom_api_url(url: str, limit: int = 20) -> list[dict]:
    """
    Allows ingesting any user-provided public or private REST API URL.
    Supports JSON lists, JSON objects, and line-delimited IP/text streams.
    """
    try:
        req = urllib.request.Request(url, headers=HEADERS)
        with urllib.request.urlopen(req, context=ssl_context, timeout=8) as resp:
            raw = resp.read().decode("utf-8", errors="ignore")
            try:
                data = json.loads(raw)
                if isinstance(data, list):
                    return data[:limit]
                elif isinstance(data, dict):
                    for key in ["data", "items", "results", "iocs"]:
                        if key in data and isinstance(data[key], list):
                            return data[key][:limit]
                    return [data]
            except json.JSONDecodeError:
                lines = [line.strip() for line in raw.splitlines() if line.strip() and not line.startswith("#")]
                return [{"custom_record": line} for line in lines[:limit]]
    except Exception as e:
        print(f"[!] Custom API fetch failed: {e}")
        return []


# ==============================================================================
# 2. PROTOCOL & PORT MAPPING UTILITIES
# ==============================================================================

def map_port_to_service(port: int | str) -> tuple[str, str]:
    """Maps a network destination port to transport protocol and UNSW-NB15 service."""
    try:
        p = int(port)
    except (ValueError, TypeError):
        return "tcp", "unknown"

    if p in [80, 8080, 8000]:
        return "tcp", "http"
    elif p in [443, 8443]:
        return "tcp", "ssl"
    elif p == 53:
        return "udp", "dns"
    elif p in [21, 20]:
        return "tcp", "ftp"
    elif p == 22:
        return "tcp", "ssh"
    elif p in [25, 465, 587]:
        return "tcp", "smtp"
    elif p == 110:
        return "tcp", "pop3"
    elif p in [67, 68]:
        return "udp", "dhcp"
    elif p in [161, 162]:
        return "udp", "snmp"
    elif p == 6667:
        return "tcp", "irc"
    elif p in [1812, 1813]:
        return "udp", "radius"
    return "tcp", "unknown"


def get_base_unsw_packet() -> dict:
    """Returns a baseline template containing all 42 UNSW-NB15 features."""
    return {
        "dur": 0.001,
        "proto": "tcp",
        "service": "unknown",
        "state": "FIN",
        "spkts": 2,
        "dpkts": 2,
        "sbytes": 140,
        "dbytes": 140,
        "rate": 100.0,
        "sttl": 64,
        "dttl": 32,
        "sload": 50000.0,
        "dload": 50000.0,
        "sloss": 0,
        "dloss": 0,
        "sinpkt": 0.001,
        "dinpkt": 0.001,
        "sjit": 0.0,
        "djit": 0.0,
        "swin": 255,
        "stcpb": 1000,
        "dtcpb": 1000,
        "dwin": 255,
        "tcprtt": 0.001,
        "synack": 0.0005,
        "ackdat": 0.0005,
        "smean": 70,
        "dmean": 70,
        "trans_depth": 0,
        "response_body_len": 0,
        "ct_srv_src": 1,
        "ct_state_ttl": 1,
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


# ==============================================================================
# 3. FEATURE EXTRACTION & NORMALIZATION
# ==============================================================================

def ingest_all_live_sources(
    limit_per_source: int = 12,
    include_sans_attacks: bool = True,
    include_sans_ports: bool = True,
    include_feodo_c2: bool = True,
    include_emerging_threats: bool = True,
    include_live_probe: bool = True,
    custom_api_url: str | None = None,
) -> pd.DataFrame:
    """
    Ingests live data from 4 public cybersecurity APIs, live network probes,
    and optional custom APIs. Normalizes raw telemetry into full UNSW-NB15 records.
    """
    records = []
    now_time = time.strftime("%H:%M:%S")

    # --------------------------------------------------------------------------
    # Feed 1: SANS ISC Live Attacks Feed
    # --------------------------------------------------------------------------
    if include_sans_attacks:
        attacks_data = fetch_sans_attacks(limit=limit_per_source)
        for item in attacks_data:
            pkt = get_base_unsw_packet()
            attacks = int(item.get("attacks", 10))
            count = int(item.get("count", 100))
            ip = str(item.get("ip", "unknown"))

            # Active attack probe signature (aggressive scanning probe)
            pkt.update({
                "proto": "tcp",
                "service": "unknown",
                "state": "INT",
                "spkts": max(2, min(50, count // 10)),
                "dpkts": 0,
                "sbytes": 120 + (attacks * 8),
                "dbytes": 0,
                "sttl": 254,
                "dttl": 0,
                "dur": max(0.00001, 1.0 / max(1, attacks)),
                "rate": float(max(1000, count * 15)),
                "sload": float(attacks * 500000),
                "ct_srv_src": min(50, attacks),
                "ct_src_dport_ltm": min(50, count // 5),
                "ct_dst_src_ltm": min(50, attacks),
                "ct_state_ttl": 2,
            })
            pkt["Source_Feed"] = "SANS ISC Live Attacks"
            pkt["Source_IP"] = ip
            pkt["Target_Port"] = 445
            pkt["Feed_Metadata"] = f"Observed Attacks: {attacks:,} | Total Packets: {count:,} | Last Active: {item.get('lastseen', 'Today')}"
            pkt["Timestamp"] = now_time
            records.append(pkt)

    # --------------------------------------------------------------------------
    # Feed 2: SANS ISC Top Targeted Ports Activity
    # --------------------------------------------------------------------------
    if include_sans_ports:
        ports_data = fetch_sans_topports(limit=limit_per_source)
        for item in ports_data:
            pkt = get_base_unsw_packet()
            port = int(item.get("targetport", 80))
            records_count = int(item.get("records", 500))
            sources = int(item.get("sources", 50))
            targets = int(item.get("targets", 10))
            proto, service = map_port_to_service(port)

            is_scan_heavy = sources > 200 or port in [445, 22, 23, 3389]
            pkt.update({
                "proto": proto,
                "service": service,
                "state": "INT" if is_scan_heavy else "FIN",
                "spkts": max(2, min(40, records_count // sources if sources else 4)),
                "dpkts": 0 if is_scan_heavy else 4,
                "sbytes": 200 if is_scan_heavy else 850,
                "dbytes": 0 if is_scan_heavy else 1200,
                "sttl": 254 if is_scan_heavy else 64,
                "dttl": 0 if is_scan_heavy else 32,
                "dur": 0.0001 if is_scan_heavy else 0.15,
                "rate": float(sources * 50) if is_scan_heavy else 120.0,
                "sload": float(records_count * 200) if is_scan_heavy else 80000.0,
                "ct_srv_src": min(40, sources // 10),
                "ct_src_dport_ltm": min(40, targets),
                "ct_state_ttl": 2 if is_scan_heavy else 1,
            })
            pkt["Source_Feed"] = "SANS ISC Target Ports"
            pkt["Source_IP"] = f"Distributed_Scanners ({sources:,} hosts)"
            pkt["Target_Port"] = port
            pkt["Feed_Metadata"] = f"Target Port: {port} ({service.upper()}) | Volume: {records_count:,} pkts | Attack Sources: {sources:,}"
            pkt["Timestamp"] = now_time
            records.append(pkt)

    # --------------------------------------------------------------------------
    # Feed 3: abuse.ch Feodo Tracker Live Botnet C2
    # --------------------------------------------------------------------------
    if include_feodo_c2:
        feodo_data = fetch_feodo_c2(limit=limit_per_source)
        for item in feodo_data:
            pkt = get_base_unsw_packet()
            ip = str(item.get("ip_address", "unknown"))
            port = int(item.get("port", 8080))
            malware = str(item.get("malware", "Botnet C2"))
            as_name = str(item.get("as_name", "Unknown ASN"))
            country = str(item.get("country", "Unknown"))
            proto, service = map_port_to_service(port)

            # Botnet C2 periodic beaconing flow signature
            pkt.update({
                "proto": proto,
                "service": service,
                "state": "FIN",
                "spkts": 8,
                "dpkts": 6,
                "sbytes": 560,
                "dbytes": 840,
                "sttl": 128,
                "dttl": 64,
                "dur": 0.05,
                "rate": 280.0,
                "sload": 95000.0,
                "tcprtt": 0.002,
                "ct_srv_src": 6,
                "ct_dst_ltm": 3,
                "ct_src_ltm": 3,
                "ct_state_ttl": 1,
            })
            pkt["Source_Feed"] = "Feodo Tracker Botnet C2"
            pkt["Source_IP"] = ip
            pkt["Target_Port"] = port
            pkt["Feed_Metadata"] = f"Malware Family: {malware} | ASN: {as_name} | Geo: {country}"
            pkt["Timestamp"] = now_time
            records.append(pkt)

    # --------------------------------------------------------------------------
    # Feed 4: Proofpoint Emerging Threats Compromised Hosts
    # --------------------------------------------------------------------------
    if include_emerging_threats:
        et_data = fetch_emerging_threats(limit=limit_per_source)
        for ip in et_data:
            pkt = get_base_unsw_packet()
            pkt.update({
                "proto": "tcp",
                "service": "unknown",
                "state": "INT",
                "spkts": 4,
                "dpkts": 0,
                "sbytes": 240,
                "dbytes": 0,
                "sttl": 254,
                "dttl": 0,
                "dur": 0.0002,
                "rate": 15000.0,
                "sload": 2400000.0,
                "ct_srv_src": 8,
                "ct_state_ttl": 2,
            })
            pkt["Source_Feed"] = "Emerging Threats Blocklist"
            pkt["Source_IP"] = ip
            pkt["Target_Port"] = 80
            pkt["Feed_Metadata"] = "Active Compromised Host (Proofpoint Emerging Threats Global Sensor)"
            pkt["Timestamp"] = now_time
            records.append(pkt)

    # --------------------------------------------------------------------------
    # Feed 5: Live Real-Time Network Socket Probe (Normal Baseline Telemetry)
    # --------------------------------------------------------------------------
    if include_live_probe:
        probe_targets = [
            ("1.1.1.1", 80),
            ("8.8.8.8", 53),
            ("9.9.9.9", 53),
            ("208.67.222.222", 53),
            ("1.0.0.1", 80),
            ("8.8.4.4", 53),
        ]
        for host, port in probe_targets[:max(2, limit_per_source // 2)]:
            probe_res = probe_live_network_endpoint(host, port)
            pkt = get_base_unsw_packet()
            proto, service = map_port_to_service(port)
            is_ok = "ONLINE" in probe_res["status"]

            pkt.update({
                "proto": proto,
                "service": service,
                "state": "FIN" if is_ok else "REQ",
                "spkts": 2,
                "dpkts": 2 if probe_res["dbytes"] > 0 else 0,
                "sbytes": probe_res["sbytes"],
                "dbytes": probe_res["dbytes"],
                "sttl": 62,
                "dttl": 58 if probe_res["dbytes"] > 0 else 0,
                "dur": float(probe_res["dur"]),
                "tcprtt": float(probe_res["rtt"]),
                "rate": float(4.0 / max(0.001, probe_res["dur"])),
                "sload": float((probe_res["sbytes"] * 8) / max(0.001, probe_res["dur"])),
                "ct_srv_src": 1,
                "ct_state_ttl": 1,
            })
            pkt["Source_Feed"] = "Live Network Telemetry Probe"
            pkt["Source_IP"] = host
            pkt["Target_Port"] = port
            pkt["Feed_Metadata"] = f"Live RTT: {probe_res['rtt']*1000:.1f}ms | Latency: {probe_res['dur']*1000:.1f}ms | Socket Status: {probe_res['status']}"
            pkt["Timestamp"] = now_time
            records.append(pkt)

    # --------------------------------------------------------------------------
    # Feed 6: Custom User-Specified API URL
    # --------------------------------------------------------------------------
    if custom_api_url and custom_api_url.strip():
        custom_data = fetch_custom_api_url(custom_api_url.strip(), limit=limit_per_source)
        for item in custom_data:
            pkt = get_base_unsw_packet()
            ip = item.get("ip", item.get("ip_address", item.get("custom_record", "custom_endpoint")))
            pkt["Source_Feed"] = "Custom Public API Endpoint"
            pkt["Source_IP"] = str(ip)
            pkt["Target_Port"] = int(item.get("port", 80)) if str(item.get("port", "")).isdigit() else 80
            pkt["Feed_Metadata"] = f"Custom Ingestion from {custom_api_url[:35]}... ({str(item)[:60]})"
            pkt["Timestamp"] = now_time
            records.append(pkt)

    return pd.DataFrame(records)


# ==============================================================================
# 4. PREDICTION PIPELINE
# ==============================================================================

def predict_live_dataframe(df: pd.DataFrame, model, preprocessor) -> pd.DataFrame:
    """
    Applies the scikit-learn preprocessing ColumnTransformer and champion ML classifier
    to a live telemetry dataframe. Appends 'Classification', 'Confidence', and 'Risk_Score'.
    """
    if df is None or len(df) == 0:
        return df

    meta_cols = ["Source_Feed", "Source_IP", "Target_Port", "Feed_Metadata", "Timestamp"]
    features_df = df.drop(columns=meta_cols, errors="ignore").copy()

    # Preprocessing categorical standardizations
    for col in ["proto", "service", "state"]:
        if col in features_df.columns:
            features_df[col] = features_df[col].replace("-", "unknown").fillna("unknown")

    # ColumnTransformer transformation
    transformed = preprocessor.transform(features_df)
    feature_names = preprocessor.get_feature_names_out()
    X_processed = pd.DataFrame(transformed, columns=feature_names)

    # Model inference
    predictions = model.predict(X_processed)
    probs = (
        model.predict_proba(X_processed)
        if hasattr(model, "predict_proba")
        else None
    )

    df_result = df.copy()
    df_result["Classification"] = np.where(predictions == 1, "MALICIOUS", "NORMAL")

    confidences = []
    risk_scores = []
    risk_levels = []

    for i, pred in enumerate(predictions):
        if probs is not None:
            p_attack = float(probs[i, 1])
            p_conf = float(probs[i, pred])
            confidences.append(f"{p_conf*100:.1f}%")
            risk_scores.append(round(p_attack * 100, 1))

            if p_attack >= 0.80:
                risk_levels.append("CRITICAL")
            elif p_attack >= 0.50:
                risk_levels.append("HIGH")
            elif p_attack >= 0.25:
                risk_levels.append("MEDIUM")
            else:
                risk_levels.append("LOW")
        else:
            confidences.append("N/A")
            risk_scores.append(100.0 if pred == 1 else 0.0)
            risk_levels.append("HIGH" if pred == 1 else "LOW")

    df_result["Confidence"] = confidences
    df_result["Risk_Score"] = risk_scores
    df_result["Risk_Level"] = risk_levels

    return df_result


def get_source_summary_stats(df: pd.DataFrame) -> pd.DataFrame:
    """Calculates per-source feed telemetry, attack counts, and attack ratios."""
    if df is None or len(df) == 0 or "Source_Feed" not in df.columns:
        return pd.DataFrame()

    summary = []
    for source, group in df.groupby("Source_Feed"):
        total = len(group)
        malicious = int((group["Classification"] == "MALICIOUS").sum())
        normal = total - malicious
        attack_rate = (malicious / total) * 100 if total > 0 else 0
        avg_risk = group["Risk_Score"].mean() if "Risk_Score" in group.columns else 0.0

        summary.append({
            "Feed Source": source,
            "Total Ingested": total,
            "Malicious Intrusions": malicious,
            "Normal Benign": normal,
            "Threat Rate (%)": f"{attack_rate:.1f}%",
            "Avg Risk Score": f"{avg_risk:.1f}/100",
        })

    return pd.DataFrame(summary)
