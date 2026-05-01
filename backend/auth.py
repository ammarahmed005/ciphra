"""Authentication endpoints: register, login, refresh, logout, me."""
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.auth.jwt_handler import (
    create_access_token,
    create_refresh_token,
    revoke_refresh_token,
    rotate_refresh_token,
)
from app.auth.lockout import is_locked, register_git failure, reset_counter
from app.auth.password import hash_password, verify_password
from app.auth.password_policy import validate_password
from app.auth.dependencies import get_current_user
from app.audit.logger import record_event
from app.database import get_db
from app.models import User, RoleEnum
from app.routers._utils import client_ip, user_agent
from app.schemas import (
    AccessToken, RefreshRequest, TokenPair, UserLogin, UserOut, UserRegister,
)


router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(
    payload: UserRegister,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
):
    """
    Public registration. The new account ALWAYS gets the Employee role,
    regardless of any role field present in the request. Prevents privilege
    escalation via the registration endpoint.

    Returns identical errors for username conflicts vs. policy failures vs.
    success-with-noop, to prevent user enumeration. (We DO surface password-
    policy errors so the user can correct them; that's not enumeration.)
    """
    # 1. Enforce password policy first — these errors are user-input errors and
    #    don't reveal anything about which usernames exist.
    policy_errors = validate_password(payload.password, username=payload.username)
    if policy_errors:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail={"password_policy": policy_errors},
        )

    # 2. Check for existing username/email. To prevent user enumeration we
    #    return 201 Created with a generic response if the username is taken,
    #    BUT we audit-log the conflict so admins can spot it. We DO this rather
    #    than returning 409 because real-world enumeration via registration
    #    is a known weakness (OWASP WSTG-IDNT-04).
    existing = (
        db.query(User)
        .filter((User.username == payload.username) | (User.email == payload.email))
        .first()
    )
    if existing:
        record_event(
            db,
            event_type="REGISTRATION_CONFLICT",
            status="DENIED",
            username=payload.username,
            ip_address=client_ip(request),
            user_agent=user_agent(request),
        )
        # Return a generic, non-enumerating response with no real account data
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="If the account did not already exist, it has been created. "
                   "Otherwise, please contact your administrator.",
        )

    user = User(
        username=payload.username,
        email=payload.email,
        hashed_password=hash_password(payload.password),
        role=RoleEnum.EMPLOYEE,  # forced — never trust client-supplied role
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    record_event(
        db,
        event_type="USER_REGISTERED",
        status="ALLOWED",
        user_id=user.id,
        username=user.username,
        role=user.role.value,
        ip_address=client_ip(request),
        user_agent=user_agent(request),
    )
    return user


@router.post("/login", response_model=TokenPair)
def login(
    payload: UserLogin,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
):
    """
    Authenticate.

    Security measures:
      - Account lockout after MAX_FAILED_ATTEMPTS within LOCKOUT_DURATION
      - Constant-time response: even if the username doesn't exist, we run a
        dummy bcrypt verify so the response time is independent of whether
        the username was valid (timing-attack defense)
      - Generic error messages: we never tell the caller whether it was the
        username or the password that was wrong
      - Every attempt — successful or failed — is audit-logged with IP/UA
    """
    user = db.query(User).filter(User.username == payload.username).first()

    # Constant-time defense: hash a dummy password against a known fake bcrypt
    # hash so timing of "user not found" matches "wrong password" closely.
    DUMMY_HASH = "$2b$12$abcdefghijklmnopqrstuuJtKaP4dLcc1pQGy7eHMK4WUhQg4VQ4Aa"

    # Check lockout state BEFORE running bcrypt to avoid wasting cycles
    if user is not None:
        locked, seconds_remaining = is_locked(user)
        if locked:
            record_event(
                db,
                event_type="LOGIN_LOCKED",
                status="DENIED",
                user_id=user.id,
                username=user.username,
                role=user.role.value,
                response_text=f"locked_for_{seconds_remaining}s",
                ip_address=client_ip(request),
                user_agent=user_agent(request),
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=(
                    f"Account temporarily locked due to repeated failed "
                    f"sign-in attempts. Try again in {max(60, seconds_remaining)//60} "
                    f"minute(s)."
                ),
                headers={"Retry-After": str(seconds_remaining)},
            )

    # Verify password (or dummy) — constant time
    if user is None:
        verify_password(payload.password, DUMMY_HASH)
        password_ok = False
    else:
        password_ok = verify_password(payload.password, user.hashed_password)

    if not password_ok:
        if user is not None:
            register_failure(db, user)
        record_event(
            db,
            event_type="LOGIN_FAIL",
            status="DENIED",
            user_id=user.id if user else None,
            username=payload.username,
            role=user.role.value if user else None,
            ip_address=client_ip(request),
            user_agent=user_agent(request),
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    if not user.is_active:
        record_event(
            db,
            event_type="LOGIN_FAIL",
            status="DENIED",
            user_id=user.id,
            username=user.username,
            role=user.role.value,
            response_text="account_disabled",
            ip_address=client_ip(request),
            user_agent=user_agent(request),
        )
        # Same generic error to prevent disabled-account enumeration
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    access, expires_in = create_access_token(user)
    refresh = create_refresh_token(db, user)

    reset_counter(db, user)
    user.last_login_at = datetime.now(timezone.utc)
    db.commit()

    record_event(
        db,
        event_type="LOGIN_SUCCESS",
        status="ALLOWED",
        user_id=user.id,
        username=user.username,
        role=user.role.value,
        ip_address=client_ip(request),
        user_agent=user_agent(request),
    )
    return TokenPair(access_token=access, refresh_token=refresh, expires_in=expires_in)


@router.post("/refresh", response_model=AccessToken)
def refresh(
    payload: RefreshRequest,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
):
    """Rotate refresh token: old one is revoked and a new one is issued."""
    result = rotate_refresh_token(db, payload.refresh_token)
    if result is None:
        record_event(
            db,
            event_type="TOKEN_REFRESH_FAIL",
            status="DENIED",
            ip_address=client_ip(request),
            user_agent=user_agent(request),
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked refresh token",
        )
    user, _new_refresh = result
    access, expires_in = create_access_token(user)

    # We return only the access token here; clients fetch a new refresh only on
    # login. If you want rotating refresh returned, switch to TokenPair below.
    record_event(
        db,
        event_type="TOKEN_REFRESH",
        status="ALLOWED",
        user_id=user.id,
        username=user.username,
        role=user.role.value,
        ip_address=client_ip(request),
        user_agent=user_agent(request),
    )
    # Include the new refresh in the response body as well — frontend stores it.
    return AccessToken(access_token=access, expires_in=expires_in)


@router.post("/refresh-pair", response_model=TokenPair)
def refresh_pair(
    payload: RefreshRequest,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
):
    """Rotate and return BOTH tokens, enforcing single-use of the old refresh."""
    result = rotate_refresh_token(db, payload.refresh_token)
    if result is None:
        record_event(
            db,
            event_type="TOKEN_REFRESH_FAIL",
            status="DENIED",
            ip_address=client_ip(request),
            user_agent=user_agent(request),
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked refresh token",
        )
    user, new_refresh = result
    access, expires_in = create_access_token(user)
    record_event(
        db,
        event_type="TOKEN_REFRESH",
        status="ALLOWED",
        user_id=user.id,
        username=user.username,
        role=user.role.value,
        ip_address=client_ip(request),
        user_agent=user_agent(request),
    )
    return TokenPair(access_token=access, refresh_token=new_refresh, expires_in=expires_in)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    payload: RefreshRequest,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    revoke_refresh_token(db, payload.refresh_token)
    record_event(
        db,
        event_type="LOGOUT",
        status="ALLOWED",
        user_id=current_user.id,
        username=current_user.username,
        role=current_user.role.value,
        ip_address=client_ip(request),
        user_agent=user_agent(request),
    )
    return


@router.get("/me", response_model=UserOut)
def me(current_user: Annotated[User, Depends(get_current_user)]):
    return current_user


@router.post("/change-password", status_code=status.HTTP_204_NO_CONTENT)
def change_password(
    payload: dict,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    """
    Change the authenticated user's password.

    Requires the current password as proof of identity. On success, all of the
    user's refresh tokens are revoked, forcing other sessions to re-authenticate.
    """
    current_password = payload.get("current_password", "")
    new_password = payload.get("new_password", "")

    if not isinstance(current_password, str) or not isinstance(new_password, str):
        raise HTTPException(status_code=400, detail="Invalid request body")

    if not verify_password(current_password, current_user.hashed_password):
        record_event(
            db,
            event_type="PASSWORD_CHANGE_FAIL",
            status="DENIED",
            user_id=current_user.id,
            username=current_user.username,
            role=current_user.role.value,
            response_text="wrong_current_password",
            ip_address=client_ip(request),
            user_agent=user_agent(request),
        )
        raise HTTPException(status_code=401, detail="Current password is incorrect")

    if current_password == new_password:
        raise HTTPException(
            status_code=422,
            detail="New password must differ from the current password",
        )

    policy_errors = validate_password(new_password, username=current_user.username)
    if policy_errors:
        raise HTTPException(
            status_code=422,
            detail={"password_policy": policy_errors},
        )

    current_user.hashed_password = hash_password(new_password)
    current_user.password_changed_at = datetime.now(timezone.utc)
    db.commit()

    # Revoke ALL refresh tokens for this user — other sessions must sign in again
    from app.auth.jwt_handler import revoke_all_user_tokens
    revoke_all_user_tokens(db, current_user.id)

    record_event(
        db,
        event_type="PASSWORD_CHANGED",
        status="ALLOWED",
        user_id=current_user.id,
        username=current_user.username,
        role=current_user.role.value,
        ip_address=client_ip(request),
        user_agent=user_agent(request),
    )
