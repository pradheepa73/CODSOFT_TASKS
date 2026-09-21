"""Upload & share panel."""
from __future__ import annotations
import requests
import streamlit as st

API = "http://localhost:8000"


def render() -> None:
    st.markdown("### Secure File Share (DropVault)")
    st.caption("Client-side AES-GCM. Server never sees plaintext.")

    user = st.text_input("User ID", value="analyst-1", key="vault_user")
    up = st.file_uploader("Choose a file", key="vault_file")

    if up and st.button("Upload & get share link", key="vault_up"):
        try:
            files = {"blob": (up.name, up.getvalue(), "application/octet-stream")}
            data = {
                "user": user,
                "filename": up.name,
                "client_pubkey": "demo-pubkey",
                "wrapped_key": "demo-wrapped",
                "nonce": "demo-nonce",
            }
            r = requests.post(f"{API}/vault/upload",
                              data=data, files=files, timeout=15)
            r.raise_for_status()
            fid = r.json()["file_id"]

            share = requests.post(
                f"{API}/vault/share/{fid}",
                json={"user": user, "ttl_seconds": 3600, "max_downloads": 1},
                timeout=5,
            ).json()
            st.success(f"Uploaded. File ID: `{fid}`")
            st.code(share["url"], language="text")
        except requests.RequestException as e:
            st.error(f"Upload failed: {e}")