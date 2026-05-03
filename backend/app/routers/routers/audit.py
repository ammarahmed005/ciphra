"""Audit log endpoints: managers and admins can view, admin-only can verify chain."""
from typing import Annotated, List, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc
from sqlalchemy.orm import Session

from app.audit.crypto import decrypt_field
from app.audit.logger import verify_chain
from app.auth.dependencies import require_role
from app.database import get_db
from app.models import AuditLog, RoleEnum, User
from app.schemas import AuditLogOut, ChainVerifyResult


router = APIRouter(prefix="/api/audit", tags=["audit"])


def _decrypt_for_view(row: AuditLog) -> dict:
    """
    Convert an AuditLog row to dict and decrypt sensitive fields. Decryption
    failures are reported as redacted markers so a viewer can spot tampered rows.
    """
    try:
        q = decrypt_field(row.query_text)
    except Exception:
        q = "[decryption-failed]"
    try:
        r = decrypt_field(row.response_text)
    except Exception:
        r = "[decryption-failed]"
    return {
        "id": row.id,
        "timestamp": row.timestamp,
        "username": row.username,
        "role": row.role,
        "event_type": row.event_type,
        "query_text": q,
        "response_text": r,
        "classification": row.classification,
        "status": row.status,
        "ip_address": row.ip_address,
        "prev_hash": row.prev_hash,
        "current_hash": row.current_hash,
    }


@router.get("/logs", response_model=List[AuditLogOut])
def list_logs(
    db: Annotated[Session, Depends(get_db)],
    _m: Annotated[User, Depends(require_role(RoleEnum.MANAGER))],
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    event_type: Optional[str] = None,
    username: Optional[str] = None,
    status_filter: Optional[str] = Query(None, alias="status"),
):
    q = db.query(AuditLog)
    if event_type:
        q = q.filter(AuditLog.event_type == event_type)
    if username:
        q = q.filter(AuditLog.username == username)
    if status_filter:
        q = q.filter(AuditLog.status == status_filter)
    rows = q.order_by(desc(AuditLog.id)).offset(offset).limit(limit).all()
    return [_decrypt_for_view(r) for r in rows]


@router.get("/verify", response_model=ChainVerifyResult)
def verify(
    db: Annotated[Session, Depends(get_db)],
    _a: Annotated[User, Depends(require_role(RoleEnum.ADMIN))],
):
    valid, first_invalid, total = verify_chain(db)
    if valid:
        return ChainVerifyResult(
            total=total, valid=True, message=f"Chain intact across {total} entries."
        )
    return ChainVerifyResult(
        total=total,
        valid=False,
        first_invalid_id=first_invalid,
        message=f"Chain broken at entry id={first_invalid}. Possible tampering.",
    )
