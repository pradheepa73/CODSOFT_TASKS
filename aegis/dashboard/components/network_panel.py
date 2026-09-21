"""Network panel — combines PacketEye (Task 1) and NetRadar (Task 4)."""
from __future__ import annotations
import pandas as pd
import requests
import streamlit as st

from aegis.dashboard.styles import sev_pill

API = "http://localhost:8000"


def render() -> None:
    st.markdown("### Network Defense")
    st.caption("PacketEye · Task 1  &  NetRadar · Task 4")

    tab1, tab2 = st.tabs(["📦 PacketEye — Packet Analysis", "📡 NetRadar — Intrusion Detection"])

    # ── TAB 1: PacketEye ─────────────────────────────────────
    with tab1:
        st.markdown("#### Flow Risk Monitor")
        st.caption(
            "Reconstructs 5-tuple flows and scores beaconing behavior "
            "(low-jitter periodic traffic = C2 heartbeat)."
        )

        col1, col2, col3 = st.columns(3)
        col1.metric("Total Flows Tracked", "—")
        col2.metric("High Risk", "—")
        col3.metric("Beaconing Flows", "—")

        st.info(
            "Live packet capture runs from the CLI:  "
            "`python -m aegis.modules.packet_eye.capture --iface Wi-Fi`  "
            "(requires Npcap + admin on Windows)."
        )

        # Show any packet_eye events from the bus
        try:
            events = requests.get(
                f"{API}/api/events",
                params={"module": "packet_eye", "limit": 50},
                timeout=3,
            ).json()
        except requests.RequestException:
            events = []

        if events:
            st.markdown("**Recent flow events**")
            df = pd.DataFrame(events)
            df["time"] = pd.to_datetime(df["ts"], unit="s").dt.strftime("%H:%M:%S")
            df["sev"] = df["severity"].apply(sev_pill)
            df["line"] = df["sev"] + " " + df["title"]
            st.markdown(
                df[["time", "line"]].to_html(escape=False, index=False),
                unsafe_allow_html=True,
            )
        else:
            st.caption("No PacketEye events yet — run the capture CLI to generate some.")

        # Sample feature reference
        with st.expander("Feature reference"):
            st.markdown("""
| Feature | Meaning |
|---------|---------|
| `beaconing` | Coefficient of variation of inter-arrival times (higher = more periodic) |
| `pps` | Packets per second |
| `syn_ratio` | Fraction of packets with SYN flag |
| `susp_port` | Destination on a known-suspicious port |
| `mean_iat` | Mean inter-arrival time (seconds) |
""")

    # ── TAB 2: NetRadar ──────────────────────────────────────
    with tab2:
        st.markdown("#### Network Intrusion Detection")
        st.caption(
            "Isolation Forest anomaly score + MITRE ATT&CK stage classifier "
            "on 29 flow features."
        )

        col1, col2, col3 = st.columns(3)
        col1.metric("Model", "IForest + GBM")
        col2.metric("Stages", "7")
        col3.metric("Rules", "4 Suricata")

        st.markdown("**MITRE ATT&CK stages detected**")
        stages = [
            "Reconnaissance",
            "InitialAccess",
            "Execution",
            "CommandAndControl",
            "Exfiltration",
            "Impact",
            "Benign",
        ]
        st.write("  ".join(f"`{s}`" for s in stages))

        st.markdown("**Suricata rules shipped**")
        st.code(
            "alert dns  ... DNS Tunneling - TXT payload > 200 bytes   (sid:9000001)\n"
            "alert ssh  ... SSH Brute Force - 8 attempts in 60s       (sid:9000002)\n"
            "alert tcp  ... SYN Port Scan - 25 SYNs in 10s            (sid:9000003)\n"
            "alert tls  ... TLS SNI on suspicious TLD                 (sid:9000004)",
            language="text",
        )

        # NetRadar events
        try:
            events = requests.get(
                f"{API}/api/events",
                params={"module": "net_radar", "limit": 50},
                timeout=3,
            ).json()
        except requests.RequestException:
            events = []

        if events:
            st.markdown("**Recent NIDS alerts**")
            df = pd.DataFrame(events)
            df["time"] = pd.to_datetime(df["ts"], unit="s").dt.strftime("%H:%M:%S")
            df["sev"] = df["severity"].apply(sev_pill)
            df["line"] = df["sev"] + " " + df["title"]
            st.markdown(
                df[["time", "line"]].to_html(escape=False, index=False),
                unsafe_allow_html=True,
            )
        else:
            st.info(
                "No NetRadar events yet. Live detection requires the NIDS module "
                "to be fed flow data. The Suricata rules and classifiers are "
                "available via `python -m aegis.modules.net_radar.anomaly`."
            )