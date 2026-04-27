"""FastAPI dependencies for authentication and role-based authorization."""
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session

from app.auth.jwt_handler import decode_access_token
from app.database import get_db
from app.models import User, RoleEnum


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")


def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    db: Annotated[Session, Depends(get_db)],
) -> User:
    """Resolve the authenticated user from the Bearer token on every request."""
    credentials_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    payload = decode_access_token(token)
    if payload is None:
        raise credentials_exc
    user_id = payload.get("sub")
    if user_id is None:
        raise credentials_exc
    try:
        user = db.get(User, int(user_id))
    except (TypeError, ValueError):
        raise credentials_exc
    if user is None or not user.is_active:
        raise credentials_exc
    return user


# Role hierarchy (higher number = more access)
_ROLE_LEVEL = {
    RoleEnum.GUEST: 0,
    RoleEnum.EMPLOYEE: 1,
    RoleEnum.MANAGER: 2,
    RoleEnum.ADMIN: 3,
}


def require_role(min_role: RoleEnum):
    """Dependency factory — require at least the given role."""
    required_level = _ROLE_LEVEL[min_role]

    def checker(current_user: Annotated[User, Depends(get_current_user)]) -> User:
        if _ROLE_LEVEL[current_user.role] < required_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires role '{min_role.value}' or higher",
            )
        return current_user

    return checker
