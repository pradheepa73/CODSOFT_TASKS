"""AEGIS Streamlit dashboard entrypoint."""
from __future__ import annotations

import sys
from pathlib import Path
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

import streamlit as st

from aegis.dashboard.styles import inject
from aegis.dashboard.components import (
    event_feed, phish_panel, code_panel, network_panel, vault_panel,
)

st.set_page_config(
    page_title="AEGIS . Cyber Defense",
    page_icon="S",
    layout="wide",
    initial_sidebar_state="expanded",
)
inject()

st.markdown(
    '<h1 class="aegis-title">AEGIS - Unified AI Cyber Defense</h1>',
    unsafe_allow_html=True,
)
st.caption("PacketEye . PhishGuard . CodeSentinel . NetRadar . DropVault")

with st.sidebar:
    st.markdown("### Modules")
    page = st.radio(
        "Navigate",
        [
            "Live Events",
            "Phishing",
            "Code Scanner",
            "Network",
            "Secure Share",
        ],
        label_visibility="collapsed",
    )
    st.divider()
    st.markdown("**AEGIS v1.0**")
    st.caption("5 tasks . 1 platform")

if page == "Live Events":
    event_feed.render()
elif page == "Phishing":
    phish_panel.render()
elif page == "Code Scanner":
    code_panel.render()
elif page == "Network":
    network_panel.render()
else:
    vault_panel.render()