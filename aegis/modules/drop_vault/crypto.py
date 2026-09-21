"""Cryptographic primitives: X25519 wrap, AES-GCM, HMAC one-time tokens."""
from __future__ import annotations
import hmac
import hashlib
import os
import time
from base64 import urlsafe_b64encode, urlsafe_b64decode

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def generate_ephemeral_keypair():
    priv = X25519PrivateKey.generate()
    priv_b = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_b = priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv_b, pub_b


def derive_shared_secret(priv_bytes, peer_pub_bytes,
                         context: bytes = b"aegis/dropvault/v1"):
    priv = X25519PrivateKey.from_private_bytes(priv_bytes)
    peer = X25519PublicKey.from_public_bytes(peer_pub_bytes)
    shared = priv.exchange(peer)
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=b"", info=context,
    ).derive(shared)


def encrypt(key, plaintext, aad: bytes = b""):
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce, ct


def decrypt(key, nonce, ct, aad: bytes = b""):
    return AESGCM(key).decrypt(nonce, ct, aad)


def make_token(secret, file_id, ttl_seconds):
    expires = int(time.time()) + ttl_seconds
    payload = f"{file_id}.{expires}".encode()
    sig = hmac.new(secret, payload, hashlib.sha256).digest()[:16]
    return urlsafe_b64encode(payload + b"." + sig).decode()


def verify_token(secret, token, file_id) -> bool:
    try:
        raw = urlsafe_b64decode(token.encode())
        payload, sig = raw.rsplit(b".", 1)
        expected = hmac.new(secret, payload, hashlib.sha256).digest()[:16]
        if not hmac.compare_digest(sig, expected):
            return False
        fid, exp = payload.decode().split(".")
        if fid != file_id:
            return False
        if int(exp) < time.time():
            return False
        return True
    except Exception:
        return False