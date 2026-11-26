"""Secrets at rest: AES-GCM encryption for provider config (v5 section 9).

The encryption key is derived from ``APP_SECRET`` with HKDF-SHA256
(info ``"quick-img-convert:provider-config"``); ``APP_SECRET`` itself
is never stored in the database. Ciphertext is base64
``nonce || ciphertext || tag`` (12-byte nonce, AES-256-GCM).

Also holds small shared helpers: email hashing for logs (never log a
full email address), IP masking for session display, and HMAC helpers
for signed cookies / device ids.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes


def _derive_key(app_secret: str) -> bytes:
    if not app_secret:
        raise ValueError("APP_SECRET is not set")
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"quick-img-convert:provider-config",
    ).derive(app_secret.encode("utf-8"))


def encrypt_config(app_secret: str, plaintext: str) -> str:
    """Encrypt a config JSON string; returns base64 nonce+ciphertext."""
    key = _derive_key(app_secret)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(nonce + ct).decode("ascii")


def decrypt_config(app_secret: str, blob: str) -> str:
    """Decrypt a blob produced by :func:`encrypt_config`."""
    key = _derive_key(app_secret)
    raw = base64.b64decode(blob.encode("ascii"))
    nonce, ct = raw[:12], raw[12:]
    return AESGCM(key).decrypt(nonce, ct, None).decode("utf-8")


def encrypt_dict(app_secret: str, data: dict) -> str:
    import json

    return encrypt_config(app_secret, json.dumps(data, sort_keys=True))


def decrypt_dict(app_secret: str, blob: str) -> dict:
    import json

    return json.loads(decrypt_config(app_secret, blob))


def hmac_hex(secret: str, message: str) -> str:
    return hmac.new(
        secret.encode("utf-8"), message.encode("utf-8"), hashlib.sha256
    ).hexdigest()


def sign_value(secret: str, value: str) -> str:
    """``value.signature`` signed-cookie format."""
    return f"{value}.{hmac_hex(secret, value)}"


def unsign_value(secret: str, signed: str) -> str | None:
    """Return the value if the signature matches, else None."""
    if not signed or "." not in signed:
        return None
    value, _, sig = signed.rpartition(".")
    if not value or not sig:
        return None
    if hmac.compare_digest(sig, hmac_hex(secret, value)):
        return value
    return None


def hash_email(email: str) -> str:
    """SHA-256 of the normalised email, for logs and auth_attempts.

    Never log a full email address (spec section 15).
    """
    return hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()


def mask_ip(ip: str | None) -> str:
    """Mask an IP for display: last octet / last hextet hidden."""
    if not ip:
        return "—"
    if ":" in ip:  # IPv6
        parts = ip.split(":")
        return ":".join(parts[:4]) + ":****"
    parts = ip.split(".")
    if len(parts) == 4:
        return ".".join(parts[:3]) + ".***"
    return ip[: max(0, len(ip) - 3)] + "***"
