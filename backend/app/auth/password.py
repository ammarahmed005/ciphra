"""
Password hashing using bcrypt directly.

We use the `bcrypt` package directly instead of passlib because newer versions
of bcrypt broke passlib's backend detection. Bcrypt truncates inputs longer
than 72 bytes, so we pre-hash overlong passwords with SHA-256.
"""
import hashlib
import bcrypt


BCRYPT_ROUNDS = 12
MAX_PASSWORD_BYTES = 72  # bcrypt's hard limit


def _encode(password: str) -> bytes:
    b = password.encode("utf-8")
    if len(b) > MAX_PASSWORD_BYTES:
        # Pre-hash with SHA-256 hex so passwords longer than 72 bytes still work.
        # The resulting hex is always 64 bytes of ASCII.
        b = hashlib.sha256(b).hexdigest().encode("ascii")
    return b


def hash_password(password: str) -> str:
    """Hash a plaintext password with bcrypt."""
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    return bcrypt.hashpw(_encode(password), salt).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    """Verify a plaintext password against a bcrypt hash in constant time."""
    try:
        return bcrypt.checkpw(_encode(plain), hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False
