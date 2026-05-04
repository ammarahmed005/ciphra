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

# ─── TOTP Core (RFC 6238) ─────────────────────────────────────────────────────

def _hotp(secret: str, counter: int) -> str:
    """
    HMAC-based OTP (RFC 4226).
    TOTP is HOTP with counter = current time window.
    """
    try:
        key = base64.b32decode(secret.upper(), casefold=True)
    except Exception:
        raise ValueError("Invalid TOTP secret — must be Base32 encoded.")

    # Pack counter as 8-byte big-endian
    msg = struct.pack(">Q", counter)

    # HMAC-SHA1
    h = hmac.new(key, msg, hashlib.sha1).digest()

    # Dynamic truncation
    offset = h[-1] & 0x0F
    code = struct.unpack(">I", h[offset:offset + 4])[0] & 0x7FFFFFFF

    return str(code % (10 ** TOTP_DIGITS)).zfill(TOTP_DIGITS)


def _current_counter(at_time: Optional[float] = None) -> int:
    """Return the current TOTP time window counter."""
    t = at_time if at_time is not None else time.time()
    return int(t // TOTP_INTERVAL)


def generate_totp_code(secret: str, at_time: Optional[float] = None) -> str:
    """
    Generate the current TOTP code for a secret.
    Useful for testing.

    Args:
        secret:  Base32 TOTP secret.
        at_time: Unix timestamp (default: now).

    Returns:
        6-digit OTP string.
    """
    return _hotp(secret, _current_counter(at_time))


def verify_totp_code(secret: str, code: str, at_time: Optional[float] = None) -> bool:
    """
    Verify a user-supplied TOTP code against the secret.
    Checks current window ± TOTP_TOLERANCE to allow for clock drift.

    Args:
        secret:  The user's Base32 TOTP secret.
        code:    The 6-digit code entered by the user.
        at_time: Unix timestamp to verify against (default: now).

    Returns:
        True if the code is valid, False otherwise.
    """
    if not secret or not code:
        return False

    # Normalise — strip spaces, must be digits only
    code = code.strip().replace(" ", "")
    if not code.isdigit() or len(code) != TOTP_DIGITS:
        logger.warning("Invalid TOTP code format supplied.")
        return False

    counter = _current_counter(at_time)

    for drift in range(-TOTP_TOLERANCE, TOTP_TOLERANCE + 1):
        expected = _hotp(secret, counter + drift)
        if hmac.compare_digest(expected, code):
            logger.info("TOTP verification succeeded (drift=%d)", drift)
            return True

    logger.warning("TOTP verification failed.")
    return False
# ─── Backup Codes ─────────────────────────────────────────────────────────────

def generate_backup_codes() -> tuple[list[str], list[str]]:
    """
    Generate one-time backup codes for account recovery.

    Returns:
        (plaintext_codes, hashed_codes)
        - Store hashed_codes in the database.
        - Show plaintext_codes to the user ONCE — they cannot be recovered.
    """
    plaintext = []
    hashed = []

    for _ in range(BACKUP_CODE_COUNT):
        # Generate a readable code like: ABCDE-FGHIJ
        raw = secrets.token_urlsafe(BACKUP_CODE_LENGTH)[:BACKUP_CODE_LENGTH].upper()
        code = f"{raw[:5]}-{raw[5:]}"
        plaintext.append(code)

        # Hash before storing — treat like passwords
        digest = hashlib.sha256(code.encode()).hexdigest()
        hashed.append(digest)

    logger.info("Generated %d backup codes.", BACKUP_CODE_COUNT)
    return plaintext, hashed


def verify_backup_code(supplied_code: str, stored_hashes: list[str]) -> tuple[bool, list[str]]:
    """
    Verify a backup code and remove it from the list (single use).

    Args:
        supplied_code:  The code the user typed.
        stored_hashes:  List of SHA-256 hashed backup codes from DB.

    Returns:
        (valid, updated_hashes)
        - valid: True if the code matched.
        - updated_hashes: The remaining codes after consuming the used one.
    """
    normalised = supplied_code.strip().upper().replace(" ", "")
    digest = hashlib.sha256(normalised.encode()).hexdigest()

    for i, stored in enumerate(stored_hashes):
        if hmac.compare_digest(digest, stored):
            remaining = stored_hashes[:i] + stored_hashes[i + 1:]
            logger.info(
                "Backup code used. %d codes remaining.", len(remaining)
            )
            return True, remaining

    logger.warning("Invalid backup code supplied.")
    return False, stored_hashes


# ─── 2FA State Helpers ────────────────────────────────────────────────────────

def is_2fa_enabled(user) -> bool:
    """Check if 2FA is enabled on a user model instance."""
    return bool(getattr(user, "totp_secret", None))


def setup_2fa(user) -> dict:
    """
    Initialise 2FA setup for a user.
    Call this when the user requests to enable 2FA.

    Returns a dict with:
      - secret: raw secret (store encrypted on user record)
      - uri:    otpauth:// URI for QR code
      - backup_codes: plaintext codes to show the user ONCE
      - backup_hashes: hashed codes to store in DB
    """
    secret = generate_totp_secret()
    uri = get_totp_uri(secret, user.username)
    plaintext_codes, hashed_codes = generate_backup_codes()

    logger.info("2FA setup initiated for user '%s'.", user.username)

    return {
        "secret": secret,
        "uri": uri,
        "backup_codes": plaintext_codes,   # show to user once
        "backup_hashes": hashed_codes,     # store in DB
    }


def disable_2fa(user) -> None:
    """
    Disable 2FA for a user.
    Clears the TOTP secret and backup codes from the user record.
    """
    logger.info("2FA disabled for user '%s'.", user.username)
    if hasattr(user, "totp_secret"):
        user.totp_secret = None
    if hasattr(user, "backup_codes"):
        user.backup_codes = []


        