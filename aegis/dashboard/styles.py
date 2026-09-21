"""Inject the AEGIS dark stylesheet into Streamlit."""
from __future__ import annotations
import streamlit as st

from aegis.dashboard.theme import DARK


def sev_pill(sev: str) -> str:
    c = DARK.get(sev, DARK["muted"])
    return (
        f'<span style="display:inline-block;padding:2px 9px;border-radius:999px;'
        f'font-family:JetBrains Mono,monospace;font-size:11px;text-transform:uppercase;'
        f'letter-spacing:.5px;background:{c}22;color:{c};border:1px solid {c}55;">'
        f'{sev}</span>'
    )


def inject() -> None:
    c = DARK
    st.markdown(f"""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Inter:wght@400;600&display=swap');
    html, body, [class*="css"] {{ font-family:'Inter',sans-serif; }}
    code, pre, .mono {{ font-family:'JetBrains Mono',monospace; }}
    .stApp {{ background:{c['bg_base']}; }}
    section[data-testid="stSidebar"] {{
        background:{c['bg_surface']};
        border-right:1px solid {c['border']};
    }}
    div[data-testid="stMetric"] {{
        background:{c['bg_surface']};
        border:1px solid {c['border']};
        border-radius:10px;
        padding:14px 18px;
    }}
    div[data-testid="stMetricValue"] {{
        color:{c['text']}; font-family:'JetBrains Mono',monospace;
    }}
    .aegis-title::after {{
        content:''; display:block; height:2px; margin-top:10px;
        background:linear-gradient(90deg,{c['brand']},{c['brand_2']},transparent);
        animation:pulse 3s ease-in-out infinite;
    }}
    @keyframes pulse {{ 0%,100%{{opacity:.35}} 50%{{opacity:1}} }}
    pre {{ background:{c['bg_elevated']} !important; border:1px solid {c['border']}; }}
    .stButton>button {{
        background:transparent; border:1px solid {c['brand']}; color:{c['text']};
        border-radius:8px; font-family:'JetBrains Mono',monospace;
    }}
    .stButton>button:hover {{
        background:{c['brand']}22; border-color:{c['brand_2']}; color:{c['brand_2']};
    }}
    </style>
    """, unsafe_allow_html=True)