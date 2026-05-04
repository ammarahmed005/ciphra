"""
Two-Factor Authentication (2FA) — CIPHRA
Implements TOTP-based 2FA compatible with Google Authenticator, Authy, etc.

Features:
  - Generate TOTP secret per user
  - Generate QR code URI for authenticator apps
  - Verify TOTP codes with time-drift tolerance
  - Backup codes generation and validation
  - Enable/disable 2FA per user
  - Audit logs every 2FA event
"""

import base64
import hashlib
import hmac
import logging
import os
import secrets
import struct
import time
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("ciphra.two_factor")


# ─── Constants ────────────────────────────────────────────────────────────────

TOTP_INTERVAL = 30          # seconds per TOTP window
TOTP_DIGITS = 6             # length of OTP code
TOTP_TOLERANCE = 1          # allow 1 window drift (±30s)
BACKUP_CODE_COUNT = 8       # number of backup codes generated
BACKUP_CODE_LENGTH = 10     # characters per backup code
APP_NAME = "CIPHRA"         # shown in authenticator app


# ─── Secret Management ────────────────────────────────────────────────────────

def generate_totp_secret() -> str:
    """
    Generate a cryptographically secure Base32 TOTP secret.
    This is stored (encrypted) on the user record.

    Returns:
        A 32-character Base32 encoded secret string.
    """
    raw = os.urandom(20)  # 160 bits — matches RFC 4226 recommendation
    return base64.b32encode(raw).decode("utf-8")


def get_totp_uri(secret: str, username: str, issuer: str = APP_NAME) -> str:
    """
    Generate an otpauth:// URI for QR code generation.
    Paste this into a QR code library to show a scannable code.

    Args:
        secret:   The user's TOTP secret (Base32).
        username: The user's username or email.
        issuer:   The app name shown in the authenticator.

    Returns:
        otpauth:// URI string.
    """
    from urllib.parse import quote
    label = quote(f"{issuer}:{username}")
    issuer_encoded = quote(issuer)
    return (
        f"otpauth://totp/{label}"
        f"?secret={secret}"
        f"&issuer={issuer_encoded}"
        f"&algorithm=SHA1"
        f"&digits={TOTP_DIGITS}"
        f"&period={TOTP_INTERVAL}"
    )