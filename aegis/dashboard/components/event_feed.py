"""Live event feed with severity filter."""
from __future__ import annotations
import pandas as pd
import requests
import streamlit as st

from aegis.dashboard.styles import sev_pill
from aegis.dashboard.theme import SEVERITY_ORDER

API = "http://localhost:8000"


def render() -> None:
    st.markdown("### Live Events")
    col1, col2 = st.columns([2, 2])
    with col1:
        sev_filter = st.selectbox(
            "Minimum severity", ["info"] + SEVERITY_ORDER[::-1], index=0,
        )
    with col2:
        module_filter = st.selectbox(
            "Module", ["all", "packet_eye", "net_radar", "code_sentinel",
                       "phish_guard", "drop_vault"],
        )

    params = {"limit": 300, "min_severity": sev_filter}
    if module_filter != "all":
        params["module"] = module_filter

    try:
        events = requests.get(f"{API}/api/events", params=params, timeout=3).json()
    except requests.RequestException as e:
        st.error(f"API unreachable: {e}")
        return

    if not events:
        st.info("No events match the filter yet.")
        return

    df = pd.DataFrame(events)
    df["time"] = pd.to_datetime(df["ts"], unit="s").dt.strftime("%H:%M:%S")
    df["severity_html"] = df["severity"].apply(sev_pill)
    df["title"] = df["severity_html"] + " " + df["title"]
    view = df[["time", "module", "title"]]
    st.markdown(view.to_html(escape=False, index=False), unsafe_allow_html=True)
    st.caption(f"{len(df)} events")