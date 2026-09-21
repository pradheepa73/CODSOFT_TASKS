"""Task 5 — Secure File Sharing (DropVault).

Zero-knowledge file sharing: client-side AES-GCM, X25519 key wrap,
HMAC one-time download tokens, EWMA access-anomaly detection.

Public API:
- router  — FastAPI router (mount in your app)
- crypto  — cryptographic primitives submodule
"""
from aegis.modules.drop_vault.server import router
from aegis.modules.drop_vault import crypto

__all__ = ["router", "crypto"]