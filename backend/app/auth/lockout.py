"""
Account lockout policy.

Enforces a temporary lockout on a user account after too many failed login
attempts within a short window. This is the OWASP-recommended brute-force
defense (ASVS V2.2.1, NIST SP 800-63B 5.2.2).

Strategy:
  - Track failed_login_count + last_failed_login_at on the user record
  - After MAX_FAILED_ATTEMPTS, lock for LOCKOUT_DURATION_MINUTES
  - Successful login resets the counter
  - Counter also resets if the last failure is older than the reset window

We keep this in the relational DB (not Redis/etc) so the audit trail and the
lockout state share the same atomic transaction. For very high-traffic systems
you'd move this to a Redis token bucket.
"""
from datetime import datetime, timedelta, timezone
from typing import Optional

from sqlalchemy.orm import Session

from app.models import User


# Tunable thresholds. In production these would come from settings.
MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15
COUNTER_RESET_MINUTES = 60  # forget failures older than this


def is_locked(user: User) -> tuple[bool, Optional[int]]:
    """
    Returns (locked, seconds_remaining).
    A user is locked if they have >= MAX_FAILED_ATTEMPTS within LOCKOUT_DURATION.
    """
    if user is None:
        return False, None
    if (user.failed_login_count or 0) < MAX_FAILED_ATTEMPTS:
        return False, None

    last = user.last_failed_login_at
    if last is None:
        return False, None
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)

    unlock_at = last + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
    now = datetime.now(timezone.utc)
    if now >= unlock_at:
        return False, None

    return True, int((unlock_at - now).total_seconds())


def register_failure(db: Session, user: User) -> None:
    """Increment failed login counter, atomically with last-failed timestamp."""
    if user is None:
        return
    now = datetime.now(timezone.utc)
    last = user.last_failed_login_at
    if last is not None and last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)

    # If their last failure was a long time ago, reset the counter to 1
    if last is None or (now - last) > timedelta(minutes=COUNTER_RESET_MINUTES):
        user.failed_login_count = 1
    else:
        user.failed_login_count = (user.failed_login_count or 0) + 1
    user.last_failed_login_at = now
    db.commit()


def reset_counter(db: Session, user: User) -> None:
    """Called after a successful login."""
    if user is None:
        return
    if user.failed_login_count or user.last_failed_login_at:
        user.failed_login_count = 0
        user.last_failed_login_at = None
        db.commit()
