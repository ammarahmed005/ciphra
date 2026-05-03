"""Admin endpoints: list users, create users, change roles, activate/deactivate."""
from typing import Annotated, List

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.audit.logger import record_event
from app.auth.dependencies import require_role
from app.auth.jwt_handler import revoke_all_user_tokens
from app.auth.password import hash_password
from app.auth.password_policy import validate_password
from app.database import get_db
from app.models import RoleEnum, User
from app.routers._utils import client_ip, user_agent
from app.schemas import AdminCreateUser, UpdateActiveRequest, UpdateRoleRequest, UserOut


router = APIRouter(prefix="/api/admin", tags=["admin"])


@router.get("/users", response_model=List[UserOut])
def list_users(
    db: Annotated[Session, Depends(get_db)],
    _admin: Annotated[User, Depends(require_role(RoleEnum.ADMIN))],
):
    return db.query(User).order_by(User.id.asc()).all()


@router.post("/users", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: AdminCreateUser,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    admin: Annotated[User, Depends(require_role(RoleEnum.ADMIN))],
):
    """
    Admin-only: create a user at any role. Use this to bootstrap manager/admin
    accounts since public registration only creates employees.
    """
    # Enforce same password policy used in public registration
    policy_errors = validate_password(payload.password, username=payload.username)
    if policy_errors:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"password_policy": policy_errors},
        )

    existing = (
        db.query(User)
        .filter((User.username == payload.username) | (User.email == payload.email))
        .first()
    )
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email already in use",
        )
    user = User(
        username=payload.username,
        email=payload.email,
        hashed_password=hash_password(payload.password),
        role=payload.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    record_event(
        db,
        event_type="USER_CREATED_BY_ADMIN",
        status="ALLOWED",
        user_id=admin.id,
        username=admin.username,
        role=admin.role.value,
        query_text=f"new_user={user.username}",
        response_text=f"role={user.role.value}",
        ip_address=client_ip(request),
        user_agent=user_agent(request),
    )
    return user


@router.patch("/users/{user_id}/role", response_model=UserOut)
def update_role(
    user_id: int,
    payload: UpdateRoleRequest,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    admin: Annotated[User, Depends(require_role(RoleEnum.ADMIN))],
):
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == admin.id:
        raise HTTPException(status_code=400, detail="Cannot change your own role")

    old_role = user.role.value
    user.role = payload.role
    db.commit()
    db.refresh(user)

    # Any active sessions should be invalidated when role changes.
    revoke_all_user_tokens(db, user.id)

    record_event(
        db,
        event_type="ROLE_CHANGED",
        status="ALLOWED",
        user_id=admin.id,
        username=admin.username,
        role=admin.role.value,
        query_text=f"target_user={user.username}",
        response_text=f"{old_role} -> {payload.role.value}",
        ip_address=client_ip(request),
        user_agent=user_agent(request),
    )
    return user


@router.patch("/users/{user_id}/active", response_model=UserOut)
def update_active(
    user_id: int,
    payload: UpdateActiveRequest,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    admin: Annotated[User, Depends(require_role(RoleEnum.ADMIN))],
):
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if user.id == admin.id:
        raise HTTPException(status_code=400, detail="Cannot disable your own account")

    user.is_active = payload.is_active
    db.commit()
    db.refresh(user)

    if not payload.is_active:
        revoke_all_user_tokens(db, user.id)

    record_event(
        db,
        event_type="USER_ACTIVE_CHANGED",
        status="ALLOWED",
        user_id=admin.id,
        username=admin.username,
        role=admin.role.value,
        query_text=f"target_user={user.username}",
        response_text=f"is_active={payload.is_active}",
        ip_address=client_ip(request),
        user_agent=user_agent(request),
    )
    return user
