"""
AES-256 encryption for sensitive values stored in the database.
Used for AI provider API keys and LDAP credentials.
"""
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os
import secrets

from app.core.config import settings


def _get_key() -> bytes:
    """Derive a 32-byte key from the ENCRYPTION_KEY setting."""
    key = settings.ENCRYPTION_KEY.encode()
    # Pad or truncate to exactly 32 bytes
    return key[:32].ljust(32, b"\x00")


def encrypt(plaintext: str) -> str:
    """Encrypt a string, returns base64-encoded ciphertext."""
    if not plaintext:
        return ""
    aesgcm = AESGCM(_get_key())
    nonce = os.urandom(12)  # 96-bit nonce for GCM
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode(), None)
    # Prefix nonce to ciphertext, then base64 encode
    return base64.b64encode(nonce + ciphertext).decode()


def decrypt(encoded: str) -> str:
    """Decrypt a base64-encoded ciphertext string."""
    if not encoded:
        return ""
    try:
        raw = base64.b64decode(encoded.encode())
        nonce, ciphertext = raw[:12], raw[12:]
        aesgcm = AESGCM(_get_key())
        return aesgcm.decrypt(nonce, ciphertext, None).decode()
    except Exception:
        return ""


def generate_token() -> str:
    """Generate a secure random agent token."""
    return secrets.token_urlsafe(32)
