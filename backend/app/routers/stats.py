"""Aggregated stats for the dashboard - reads from audit_logs."""
from datetime import datetime, timedelta, timezone
from typing import Annotated, List, Dict, Any

from fastapi import APIRouter, Depends
from sqlalchemy import func, desc
from sqlalchemy.orm import Session

from app.audit.logger import verify_chain
from app.auth.dependencies import get_current_user
from app.database import get_db
from app.models import AuditLog, RoleEnum, User


router = APIRouter(prefix="/api/stats", tags=["stats"])


@router.get("/dashboard")
def dashboard(
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
) -> Dict[str, Any]:
    """
    Returns aggregated stats. Regular users see only their own counts; managers
    and admins see organisation-wide stats. Admins additionally get chain status.
    """
    is_privileged = current_user.role in (RoleEnum.MANAGER, RoleEnum.ADMIN)
    now = datetime.now(timezone.utc)
    day_ago = now - timedelta(hours=24)
    week_ago = now - timedelta(days=7)

    base = db.query(AuditLog)
    if not is_privileged:
        base = base.filter(AuditLog.user_id == current_user.id)

    # --- top line counts ---
    total_queries = base.filter(AuditLog.event_type == "QUERY").count()
    queries_24h = base.filter(
        AuditLog.event_type == "QUERY",
        AuditLog.timestamp >= day_ago,
    ).count()
    denied_total = base.filter(
        AuditLog.event_type.in_(["QUERY_DENIED", "PROMPT_INJECTION_BLOCKED"])
    ).count()
    denied_24h = base.filter(
        AuditLog.event_type.in_(["QUERY_DENIED", "PROMPT_INJECTION_BLOCKED"]),
        AuditLog.timestamp >= day_ago,
    ).count()

    failed_logins_24h = (
        db.query(AuditLog)
        .filter(AuditLog.event_type == "LOGIN_FAIL", AuditLog.timestamp >= day_ago)
        .count()
        if is_privileged else 0
    )
    injection_attempts_7d = base.filter(
        AuditLog.event_type == "PROMPT_INJECTION_BLOCKED",
        AuditLog.timestamp >= week_ago,
    ).count()

    # --- classification breakdown ---
    cls_rows = (
        base.filter(
            AuditLog.classification.isnot(None),
            AuditLog.timestamp >= week_ago,
        )
        .with_entities(AuditLog.classification, func.count(AuditLog.id))
        .group_by(AuditLog.classification)
        .all()
    )
    classifications = {row[0]: row[1] for row in cls_rows}
    for k in ("public", "internal", "confidential", "restricted"):
        classifications.setdefault(k, 0)

    # --- recent activity ---
    recent_q = base.order_by(desc(AuditLog.id)).limit(8).all()
    recent = [
        {
            "id": r.id,
            "timestamp": r.timestamp.isoformat(),
            "username": r.username,
            "role": r.role,
            "event_type": r.event_type,
            "status": r.status,
            "classification": r.classification,
        }
        for r in recent_q
    ]

    # --- user count and chain status (admin extras) ---
    extras: Dict[str, Any] = {}
    if current_user.role == RoleEnum.ADMIN:
        extras["total_users"] = db.query(User).count()
        extras["active_users"] = db.query(User).filter(User.is_active == True).count()  # noqa: E712
        valid, first_invalid, total_logs = verify_chain(db)
        extras["chain"] = {
            "valid": valid,
            "first_invalid_id": first_invalid,
            "total": total_logs,
        }
    elif current_user.role == RoleEnum.MANAGER:
        extras["total_users"] = db.query(User).count()
        extras["active_users"] = db.query(User).filter(User.is_active == True).count()  # noqa: E712

    return {
        "scope": "global" if is_privileged else "self",
        "now": now.isoformat(),
        "counters": {
            "total_queries": total_queries,
            "queries_24h": queries_24h,
            "denied_total": denied_total,
            "denied_24h": denied_24h,
            "failed_logins_24h": failed_logins_24h,
            "injection_attempts_7d": injection_attempts_7d,
        },
        "classifications": classifications,
        "recent": recent,
        **extras,
    }
