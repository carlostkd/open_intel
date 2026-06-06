"""
Encryption utilities for user API keys.

Uses Fernet (AES-128-CBC) with a key derived from JWT_SECRET so that
no new secret needs to be distributed — only the existing JWT_SECRET
is required.
"""

import base64
import hashlib

from cryptography.fernet import Fernet


def _get_fernet() -> Fernet:
    from config import JWT_SECRET
    key_bytes = hashlib.sha256(JWT_SECRET.encode()).digest()
    fernet_key = base64.urlsafe_b64encode(key_bytes)
    return Fernet(fernet_key)


def encrypt_api_key(plaintext: str) -> str:
    if not plaintext:
        return ""
    return _get_fernet().encrypt(plaintext.encode()).decode()


def decrypt_api_key(ciphertext: str) -> str:
    if not ciphertext:
        return ""
    try:
        return _get_fernet().decrypt(ciphertext.encode()).decode()
    except Exception:
        return ""
