"""Phishing checker panel."""
from __future__ import annotations
import requests
import streamlit as st

API = "http://localhost:8000"


def render() -> None:
    st.markdown("### Phishing Analyzer")
    st.caption("Paste a raw email (headers + body) for a multi-signal verdict.")
    text = st.text_area("Email content", height=260, key="phish_input")

    if st.button("Analyze", key="phish_btn") and text.strip():
        try:
            r = requests.post(f"{API}/api/phish", json={"text": text}, timeout=10)
            r.raise_for_status()
            res = r.json()
        except requests.RequestException as e:
            st.error(f"Analysis failed: {e}")
            return

        if res["is_phishing"]:
            st.error(f"Phishing - score {res['score']:.2%}")
        else:
            st.success(f"Legitimate - score {res['score']:.2%}")

        b = res["breakdown"]
        c1, c2, c3 = st.columns(3)
        c1.metric("URL head", f"{b['url']:.0%}")
        c2.metric("Text head", f"{b['text']:.0%}")
        c3.metric("Header head", f"{b['header']:.0%}")

        if res["signals"]:
            st.markdown("**Signals**")
            for s in res["signals"]:
                st.markdown(f"- {s}")