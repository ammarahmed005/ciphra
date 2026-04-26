"""
Tamper-evident audit logger with at-rest encryption.

Each log entry stores:
    prev_hash = current_hash of the previous entry (or genesis seed for the first)
    current_hash = sha256(prev_hash || canonical_serialization_of_entry)

The canonical form is computed BEFORE encryption — i.e., the chain hashes the
plaintext content. This way:
  - The chain still detects tampering of the underlying data
  - Sensitive fields (queries, responses) are not readable even with DB access
  - On verification we decrypt then re-hash the plaintext

Important constraints:
- The audit_logs table is append-only at both the application layer AND the DB
  layer (see init.sql trigger that REVOKEs UPDATE/DELETE).
- Sensitive text fields (query_text, response_text) are encrypted with AES-256-GCM.
"""
import hashlib
import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.audit.crypto import decrypt_field, encrypt_field
from app.config import settings
from app.models import AuditLog


logger = logging.getLogger(__name__)


def _canonical(entry: AuditLog, *, plaintext_query: Optional[str] = None,
               plaintext_response: Optional[str] = None) -> str:
    """
    Stable string representation for hashing.

    The chain hashes PLAINTEXT content, not encrypted ciphertext, because GCM
    nonces are random and would change the hash on every re-encryption. By
    hashing the plaintext we guarantee that any tampering with the underlying
    data is detected on verification (which decrypts before recomputing).
    """
    ts = entry.timestamp
    if ts is None:
        ts_str = ""
    else:
        if ts.tzinfo is not None:
            ts = ts.astimezone(timezone.utc).replace(tzinfo=None)
        ts_str = ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond:06d}"

    # If plaintexts were passed (during initial write), use those.
    # Otherwise (during verification), decrypt the stored values.
    q_text = plaintext_query if plaintext_query is not None else (
        decrypt_field(entry.query_text) or "" if entry.query_text else ""
    )
    r_text = plaintext_response if plaintext_response is not None else (
        decrypt_field(entry.response_text) or "" if entry.response_text else ""
    )

    parts = [
        ts_str,
        str(entry.user_id or ""),
        entry.username or "",
        entry.role or "",
        entry.event_type or "",
        q_text,
        r_text,
        entry.classification or "",
        entry.status or "",
        entry.ip_address or "",
        entry.user_agent or "",
    ]
    return "||".join(parts)


def _compute_hash(prev_hash: str, canonical: str) -> str:
    h = hashlib.sha256()
    h.update(prev_hash.encode("utf-8"))
    h.update(b"|")
    h.update(canonical.encode("utf-8"))
    return h.hexdigest()


def _genesis_hash() -> str:
    return hashlib.sha256(
        f"GENESIS::{settings.AUDIT_GENESIS_SEED}".encode("utf-8")
    ).hexdigest()


def _last_hash(db: Session) -> str:
    last = db.query(AuditLog).order_by(desc(AuditLog.id)).first()
    if last is None:
        return _genesis_hash()
    return last.current_hash


def record_event(
    db: Session,
    *,
    event_type: str,
    status: str,
    user_id: Optional[int] = None,
    username: Optional[str] = None,
    role: Optional[str] = None,
    query_text: Optional[str] = None,
    response_text: Optional[str] = None,
    classification: Optional[str] = None,
    ip_address: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> AuditLog:
    """Append a new audit entry. Sensitive text fields are encrypted at rest."""
    prev_hash = _last_hash(db)
    now = datetime.now(timezone.utc)

    # Encrypt sensitive content before persisting
    enc_query = encrypt_field(query_text)
    enc_response = encrypt_field(response_text)

    entry = AuditLog(
        timestamp=now,
        user_id=user_id,
        username=username,
        role=role,
        event_type=event_type,
        query_text=enc_query,
        response_text=enc_response,
        classification=classification,
        status=status,
        ip_address=ip_address,
        user_agent=user_agent,
        prev_hash=prev_hash,
        current_hash="",
    )
    # Hash the plaintext form, not the ciphertext (so the chain still detects tampering)
    entry.current_hash = _compute_hash(
        prev_hash,
        _canonical(entry, plaintext_query=query_text, plaintext_response=response_text),
    )

    db.add(entry)
    db.commit()
    db.refresh(entry)
    return entry


def verify_chain(db: Session) -> tuple[bool, Optional[int], int]:
    """
    Replay every row, decrypt sensitive fields, and check the chain.
    Returns (valid, first_invalid_id_or_None, total_rows).
    """
    expected_prev = _genesis_hash()
    total = 0
    for row in db.query(AuditLog).order_by(AuditLog.id.asc()).yield_per(500):
        total += 1
        if row.prev_hash != expected_prev:
            return False, row.id, total
        try:
            recomputed = _compute_hash(row.prev_hash, _canonical(row))
        except Exception:
            # Decryption failed — treat as tampered
            return False, row.id, total
        if recomputed != row.current_hash:
            return False, row.id, total
        expected_prev = row.current_hash
    return True, None, total


def decrypt_log_for_display(entry: AuditLog) -> dict:
    """
    Decrypt sensitive fields for an authorized viewer (admin/manager).
    Used by the audit log API to return readable content.
    """
    return {
        "query_text": decrypt_field(entry.query_text),
        "response_text": decrypt_field(entry.response_text),
    }
