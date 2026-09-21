"""Secure Code Assessment panel (Task 3)."""
from __future__ import annotations
import requests
import streamlit as st

API = "http://localhost:8000"

SAMPLE_VULN = '''import os
import sqlite3
import pickle
from flask import Flask, request

app = Flask(__name__)
SECRET_KEY = "supersecret_change_me"

@app.route("/login")
def login():
    user = request.args.get("user")
    pw = request.args.get("pw")
    cur = sqlite3.connect(":memory:").cursor()
    cur.execute("SELECT * FROM users WHERE name=?"+" AND pw=?")
    return {"ok": True}

@app.route("/run")
def run():
    cmd = request.args.get("cmd")
    os.system(cmd)
    return {"ran": cmd}

@app.route("/calc")
def calc():
    expr = request.args.get("e")
    return {"result": eval(expr)}
'''


def render() -> None:
    st.markdown("### Secure Code Assessment (CodeSentinel)")
    st.caption("AST taint analysis + lexical rules. Catches multi-line data flows regex misses.")

    col1, col2 = st.columns([3, 1])
    with col1:
        st.markdown("**Python source**")
    with col2:
        if st.button("Load sample", key="code_sample"):
            st.session_state["code_input"] = SAMPLE_VULN

    code = st.text_area(
        "Paste Python source",
        height=280,
        key="code_input",
        label_visibility="collapsed",
    )

    if st.button("Scan", key="code_scan_btn") and code.strip():
        try:
            r = requests.post(
                f"{API}/api/code/scan",
                json={"source": code, "path": "<inline>"},
                timeout=10,
            )
            r.raise_for_status()
            res = r.json()
        except requests.RequestException as e:
            st.error(f"Scan failed: {e}")
            return

        sev = res["severity"]
        score = res["score"]
        total = res["summary"]["total"]

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Severity", sev.upper())
        c2.metric("Score", f"{score:.2f}")
        c3.metric("Findings", total)
        c4.metric("Taint / Rules",
                  f"{res['summary']['taint']} / {res['summary']['rules']}")

        if sev in ("critical", "high"):
            st.error(f"Risk level: {sev.upper()}")
        elif sev == "medium":
            st.warning(f"Risk level: {sev.upper()}")
        else:
            st.success(f"Risk level: {sev.upper()}")

        if res["taint_findings"]:
            st.markdown("#### Taint findings")
            for f in res["taint_findings"]:
                with st.expander(
                    f"Line {f['line']} · {f['sink']} · from {f['source']}"
                ):
                    st.code(f["snippet"], language="python")

        if res["rule_findings"]:
            st.markdown("#### Lexical findings")
            for f in res["rule_findings"]:
                with st.expander(f"Line {f['line']} · {f['rule']}"):
                    st.code(f["snippet"], language="python")

        if not res["taint_findings"] and not res["rule_findings"]:
            st.info("No issues detected.")