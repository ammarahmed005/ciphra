"""JSON Web Token issuance, verification, and refresh rotation."""
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import uuid4

from jose import JWTError, jwt
from sqlalchemy.orm import Session

from app.config import settings
from app.models import User, RefreshToken


# ---------- Access token ----------
def create_access_token(user: User) -> tuple[str, int]:
    """Issue a short-lived access token with role claim. Returns (token, expires_in_seconds)."""
    expire_delta = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user.id),
        "username": user.username,
        "role": user.role.value,
        "type": "access",
        "iat": int(now.timestamp()),
        "exp": int((now + expire_delta).timestamp()),
        "jti": uuid4().hex,
    }
    token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return token, int(expire_delta.total_seconds())


def decode_access_token(token: str) -> Optional[dict]:
    """Decode an access token. Returns the payload or None on failure."""
    try:
        payload = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
        if payload.get("type") != "access":
            return None
        return payload
    except JWTError:
        return None


# ---------- Refresh token (opaque, server-tracked) ----------
def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()




def create_refresh_token(db: Session, user: User) -> str:
    """Create an opaque refresh token, store its hash, return the plaintext token."""
    token = secrets.token_urlsafe(48)
    token_hash = _hash_token(token)
    expires_at = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

    db_token = RefreshToken(
        user_id=user.id,
        token_hash=token_hash,
        expires_at=expires_at,
    )
    db.add(db_token)
    db.commit()
    return token


def rotate_refresh_token(db: Session, old_token: str) -> Optional[tuple[User, str]]:
    """
    Rotate a refresh token: revoke the old one and issue a new one.
    Returns (user, new_plaintext_token) on success, None on failure.
    If the presented token is already revoked, we revoke ALL the user's tokens
    (possible replay/theft). This is the OWASP-recommended refresh rotation pattern.
    """
    old_hash = _hash_token(old_token)
    db_token = db.query(RefreshToken).filter(RefreshToken.token_hash == old_hash).first()
    if db_token is None:
        return None

    now = datetime.now(timezone.utc)
    # Compare as timezone-aware
    expires_at = db_token.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=timezone.utc)
    if expires_at < now:
        return None

    if db_token.revoked:
        # Reuse detected — revoke the entire family for this user.
        db.query(RefreshToken).filter(RefreshToken.user_id == db_token.user_id).update(
            {"revoked": True}
        )
        db.commit()
        return None

    user = db_token.user
    if not user or not user.is_active:
        return None

    # Issue a new token, mark the old one revoked + linked.
    new_plain = secrets.token_urlsafe(48)
    new_hash = _hash_token(new_plain)
    expires = now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

    db.add(RefreshToken(user_id=user.id, token_hash=new_hash, expires_at=expires))
    db_token.revoked = True
    db_token.replaced_by = new_hash
    db.commit()

    return user, new_plain


def revoke_refresh_token(db: Session, token: str) -> bool:
    token_hash = _hash_token(token)
    db_token = db.query(RefreshToken).filter(RefreshToken.token_hash == token_hash).first()
    if db_token is None:
        return False
    db_token.revoked = True
    db.commit()
    return True


def revoke_all_user_tokens(db: Session, user_id: int) -> int:
    """Revoke all refresh tokens for a user. Returns count revoked."""
    updated = (
        db.query(RefreshToken)
        .filter(RefreshToken.user_id == user_id, RefreshToken.revoked.is_(False))
        .update({"revoked": True})
    )
    db.commit()
    return updated
