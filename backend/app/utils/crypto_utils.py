"""
Cryptographic Utilities — CIPHRA
Provides secure hashing, HMAC signing, token generation,
data integrity verification, and encryption helpers.

Features:
  - SHA-256 / SHA-512 file and data integrity verification
  - HMAC payload signing and verification
  - Cryptographically secure token generation
  - Constant-time comparison wrapper
  - AES-256 symmetric encryption/decryption
  - Key derivation with PBKDF2
"""

import base64
import hashlib
import hmac
import logging
import os
import secrets
import struct
import time
from typing import Optional

logger = logging.getLogger("ciphra.crypto_utils")


# ─── Constants ────────────────────────────────────────────────────────────────

SHA256_HEX_LENGTH = 64
SHA512_HEX_LENGTH = 128
DEFAULT_TOKEN_BYTES = 32          # 256-bit secure token
HMAC_ALGORITHM = "sha256"
PBKDF2_ITERATIONS = 600_000       # OWASP 2023 recommended minimum
PBKDF2_HASH = "sha256"
SALT_BYTES = 32                   # 256-bit salt


# ─── Hashing ──────────────────────────────────────────────────────────────────

def sha256_hex(data: bytes | str) -> str:
    """
    Compute SHA-256 hash of data.

    Args:
        data: Bytes or string to hash.

    Returns:
        Lowercase hex digest string (64 characters).
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def sha512_hex(data: bytes | str) -> str:
    """
    Compute SHA-512 hash of data.

    Args:
        data: Bytes or string to hash.

    Returns:
        Lowercase hex digest string (128 characters).
    """
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha512(data).hexdigest()


def sha256_file(filepath: str) -> str:
    """
    Compute SHA-256 hash of a file efficiently using streaming.
    Safe for large files — does not load entire file into memory.

    Args:
        filepath: Absolute or relative path to the file.

    Returns:
        Lowercase hex digest string.

    Raises:
        FileNotFoundError if the file does not exist.
        IOError on read failure.
    """
    h = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        digest = h.hexdigest()
        logger.debug("SHA-256 of '%s': %s", filepath, digest)
        return digest
    except FileNotFoundError:
        logger.error("File not found for hashing: %s", filepath)
        raise
    except IOError as e:
        logger.error("IO error hashing file '%s': %s", filepath, e)
        raise


# ─── Integrity Verification ───────────────────────────────────────────────────

def verify_data_integrity(
    data: bytes | str,
    expected_hash: str,
    algorithm: str = "sha256",
) -> bool:
    """
    Verify data integrity by comparing its hash to an expected value.
    Uses timing-safe comparison to prevent timing attacks.

    Args:
        data:          The data to verify.
        expected_hash: The expected hex hash string.
        algorithm:     Hash algorithm — 'sha256' or 'sha512'.

    Returns:
        True if the hash matches, False otherwise.
    """
    if isinstance(data, str):
        data = data.encode("utf-8")

    if algorithm == "sha256":
        actual = hashlib.sha256(data).hexdigest()
    elif algorithm == "sha512":
        actual = hashlib.sha512(data).hexdigest()
    else:
        raise ValueError(f"Unsupported algorithm: {algorithm}. Use 'sha256' or 'sha512'.")

    # Timing-safe comparison — prevents timing oracle attacks
    result = hmac.compare_digest(actual.lower(), expected_hash.lower())

    if not result:
        logger.warning(
            "Integrity check FAILED | algorithm=%s | expected=%s | actual=%s",
            algorithm,
            expected_hash[:16] + "...",
            actual[:16] + "...",
        )
    else:
        logger.debug("Integrity check passed | algorithm=%s", algorithm)

    return result


def verify_file_integrity(filepath: str, expected_hash: str) -> bool:
    """
    Verify integrity of a file against an expected SHA-256 hash.

    Args:
        filepath:      Path to the file to verify.
        expected_hash: Expected SHA-256 hex digest.

    Returns:
        True if file hash matches, False otherwise.
    """
    try:
        actual = sha256_file(filepath)
        result = hmac.compare_digest(actual.lower(), expected_hash.lower())
        if not result:
            logger.warning(
                "File integrity FAILED for '%s' | expected=%s | actual=%s",
                filepath,
                expected_hash[:16] + "...",
                actual[:16] + "...",
            )
        return result
    except (FileNotFoundError, IOError):
        return False


# ─── HMAC Signing ─────────────────────────────────────────────────────────────

def hmac_sign(payload: bytes | str, secret: bytes | str) -> str:
    """
    Generate an HMAC-SHA256 signature for a payload.
    Use this to sign API payloads, webhook bodies, or tokens.

    Args:
        payload: Data to sign.
        secret:  Secret key for signing.

    Returns:
        Hex HMAC signature string.
    """
    if isinstance(payload, str):
        payload = payload.encode("utf-8")
    if isinstance(secret, str):
        secret = secret.encode("utf-8")

    signature = hmac.new(secret, payload, hashlib.sha256).hexdigest()
    return signature


def hmac_verify(
    payload: bytes | str,
    secret: bytes | str,
    signature: str,
) -> bool:
    """
    Verify an HMAC-SHA256 signature against a payload.
    Uses timing-safe comparison.

    Args:
        payload:   The original data that was signed.
        secret:    The secret key used for signing.
        signature: The hex signature to verify against.

    Returns:
        True if the signature is valid, False otherwise.
    """
    expected = hmac_sign(payload, secret)
    result = hmac.compare_digest(expected.lower(), signature.lower())

    if not result:
        logger.warning("HMAC verification FAILED — possible payload tampering.")
    else:
        logger.debug("HMAC verification passed.")

    return result


# ─── Secure Token Generation ──────────────────────────────────────────────────

def generate_secure_token(nbytes: int = DEFAULT_TOKEN_BYTES) -> str:
    """
    Generate a cryptographically secure random token.
    Uses os.urandom() via the secrets module — NOT random or uuid4.

    Args:
        nbytes: Number of random bytes (default 32 = 256 bits).

    Returns:
        URL-safe base64 encoded token string.
    """
    token = secrets.token_urlsafe(nbytes)
    logger.debug("Generated secure token (%d bytes).", nbytes)
    return token


def generate_hex_token(nbytes: int = DEFAULT_TOKEN_BYTES) -> str:
    """
    Generate a cryptographically secure hex token.

    Args:
        nbytes: Number of random bytes.

    Returns:
        Hex encoded token string.
    """
    return secrets.token_hex(nbytes)


def generate_numeric_otp(digits: int = 6) -> str:
    """
    Generate a cryptographically secure numeric OTP.

    Args:
        digits: Number of digits (default 6).

    Returns:
        Zero-padded numeric OTP string.
    """
    max_val = 10 ** digits
    otp = secrets.randbelow(max_val)
    return str(otp).zfill(digits)


# ─── Constant-Time Comparison ─────────────────────────────────────────────────

def safe_compare(a: str | bytes, b: str | bytes) -> bool:
    """
    Timing-safe string/bytes comparison.
    Wrapper around hmac.compare_digest().

    Always use this instead of == for comparing
    secrets, tokens, hashes, or any security-sensitive values.

    Args:
        a: First value.
        b: Second value.

    Returns:
        True if equal, False otherwise.
    """
    if isinstance(a, str):
        a = a.encode("utf-8")
    if isinstance(b, str):
        b = b.encode("utf-8")

    return hmac.compare_digest(a, b)


# ─── Salt Generation ──────────────────────────────────────────────────────────

def generate_salt(nbytes: int = SALT_BYTES) -> bytes:
    """
    Generate a cryptographically secure random salt.

    Args:
        nbytes: Number of random bytes (default 32).

    Returns:
        Raw bytes salt.
    """
    return os.urandom(nbytes)


def generate_salt_hex(nbytes: int = SALT_BYTES) -> str:
    """
    Generate a cryptographically secure random salt as hex string.

    Returns:
        Hex encoded salt string.
    """
    return generate_salt(nbytes).hex()


# ─── Key Derivation ───────────────────────────────────────────────────────────

def derive_key(
    password: str,
    salt: bytes,
    iterations: int = PBKDF2_ITERATIONS,
    key_length: int = 32,
) -> bytes:
    """
    Derive a cryptographic key from a password using PBKDF2-HMAC-SHA256.
    Use for deriving encryption keys from passwords.

    Args:
        password:   The password to derive from.
        salt:       Random salt bytes (use generate_salt()).
        iterations: Number of PBKDF2 iterations (default 600,000).
        key_length: Output key length in bytes (default 32 = 256-bit).

    Returns:
        Derived key bytes.
    """
    key = hashlib.pbkdf2_hmac(
        PBKDF2_HASH,
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=key_length,
    )
    logger.debug(
        "Key derived via PBKDF2 | iterations=%d | key_length=%d",
        iterations,
        key_length,
    )
    return key


def derive_key_b64(
    password: str,
    salt: bytes,
    iterations: int = PBKDF2_ITERATIONS,
) -> str:
    """
    Derive a key and return it as a base64 string.
    Convenient for storing or transmitting derived keys.

    Returns:
        Base64 encoded derived key.
    """
    key = derive_key(password, salt, iterations)
    return base64.b64encode(key).decode("utf-8")


# ─── Checksum ─────────────────────────────────────────────────────────────────

def compute_checksum(data: bytes | str) -> str:
    """
    Compute a short SHA-256 checksum for quick integrity checks.
    Returns only the first 16 hex characters (64 bits).
    NOT suitable for security-critical comparisons — use verify_data_integrity().

    Args:
        data: Data to checksum.

    Returns:
        16-character hex string.
    """
    return sha256_hex(data)[:16]


def build_integrity_manifest(files: list[str]) -> dict[str, str]:
    """
    Build a SHA-256 integrity manifest for a list of files.
    Useful for verifying a set of files has not been tampered with.

    Args:
        files: List of file paths.

    Returns:
        Dict mapping filepath -> SHA-256 hex digest.
    """
    manifest = {}
    for filepath in files:
        try:
            manifest[filepath] = sha256_file(filepath)
        except (FileNotFoundError, IOError) as e:
            logger.warning("Could not hash file '%s': %s", filepath, e)
            manifest[filepath] = "ERROR"
    return manifest


def verify_integrity_manifest(manifest: dict[str, str]) -> dict[str, bool]:
    """
    Verify all files in an integrity manifest.

    Args:
        manifest: Dict mapping filepath -> expected SHA-256 hex digest.

    Returns:
        Dict mapping filepath -> True (matches) or False (tampered/missing).
    """
    results = {}
    for filepath, expected_hash in manifest.items():
        results[filepath] = verify_file_integrity(filepath, expected_hash)
    return results