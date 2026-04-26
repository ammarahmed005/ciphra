"""
AES-GCM encryption for sensitive audit log fields.

The proposal calls for "encrypted logging." We use authenticated encryption
(AES-256-GCM) to protect query/response text in the audit log. The hash chain
already provides tamper evidence, but encryption ensures that an attacker who
gains read access to the database cannot harvest sensitive query content.

Key derivation:
  - The master key comes from settings.AUDIT_ENCRYPTION_KEY
  - If unset, we derive one deterministically from JWT_SECRET_KEY + a fixed salt
    (so dev environments work zero-config; production should set the key explicitly)
  - The key is 32 bytes (256 bits)

Wire format (base64):
  [ 12 bytes nonce | ciphertext | 16 bytes GCM tag ]
"""
import base64
import hashlib
import os
from typing import Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.config import settings


_NONCE_BYTES = 12
_KEY_BYTES = 32
_PREFIX = "enc:v1:"   # so we can recognize encrypted values and rotate algorithms later


def _derive_key() -> bytes:
    """
    Derive the symmetric key. Prefer the explicit AUDIT_ENCRYPTION_KEY setting;
    fall back to a deterministic derivation from JWT_SECRET_KEY for dev convenience.
    """
    explicit = getattr(settings, "AUDIT_ENCRYPTION_KEY", "")
    if explicit:
        # Allow either hex (64 chars) or base64
        try:
            if len(explicit) == 64:
                return bytes.fromhex(explicit)
            raw = base64.b64decode(explicit)
            if len(raw) == _KEY_BYTES:
                return raw
        except Exception:
            pass
        # Last resort: hash whatever the operator gave us into 32 bytes
        return hashlib.sha256(explicit.encode("utf-8")).digest()

    # Dev fallback — hash JWT secret with a fixed salt so it's stable per deployment
    return hashlib.sha256(
        b"ciphra-audit-encryption-v1::" + settings.JWT_SECRET_KEY.encode("utf-8")
    ).digest()


_KEY = _derive_key()
_AESGCM = AESGCM(_KEY)


def encrypt_field(plaintext: Optional[str]) -> Optional[str]:
    """Return base64(nonce || ciphertext_with_tag), prefixed for versioning."""
    if plaintext is None or plaintext == "":
        return plaintext
    nonce = os.urandom(_NONCE_BYTES)
    ct = _AESGCM.encrypt(nonce, plaintext.encode("utf-8"), associated_data=None)
    return _PREFIX + base64.b64encode(nonce + ct).decode("ascii")


def decrypt_field(value: Optional[str]) -> Optional[str]:
    """Decrypt a previously encrypted value. Pass-through for unencrypted/empty."""
    if value is None or value == "":
        return value
    if not value.startswith(_PREFIX):
        # legacy / unencrypted entry — return as-is for backward compatibility
        return value
    raw = base64.b64decode(value[len(_PREFIX):])
    nonce, ct = raw[:_NONCE_BYTES], raw[_NONCE_BYTES:]
    return _AESGCM.decrypt(nonce, ct, associated_data=None).decode("utf-8")
