"""Pydantic schemas for request/response validation."""
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, EmailStr, Field, ConfigDict

from app.models import RoleEnum, SensitivityEnum


# === Auth ===
class UserRegister(BaseModel):
    """
    Public registration always creates an Employee account. Role is intentionally
    NOT accepted from the request body — accepting it would let anyone self-elevate
    to admin. Admins promote users from the admin panel post-registration.
    """
    username: str = Field(..., min_length=3, max_length=64, pattern=r"^[a-zA-Z0-9_.-]+$")
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)


class AdminCreateUser(BaseModel):
    """Admin-only user creation; can specify role."""
    username: str = Field(..., min_length=3, max_length=64, pattern=r"^[a-zA-Z0-9_.-]+$")
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)
    role: RoleEnum = RoleEnum.EMPLOYEE


class UserLogin(BaseModel):
    username: str = Field(..., min_length=1, max_length=64)
    password: str = Field(..., min_length=1, max_length=128)


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds


class RefreshRequest(BaseModel):
    refresh_token: str


class AccessToken(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    username: str
    email: str
    role: RoleEnum
    is_active: bool
    created_at: datetime
    last_login_at: Optional[datetime] = None


# === Chat ===
class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=4000)


class ChatResponse(BaseModel):
    status: str  # "allowed" | "denied"
    classification: SensitivityEnum
    reply: str
    reason: Optional[str] = None


# === Audit ===
class AuditLogOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    timestamp: datetime
    username: Optional[str]
    role: Optional[str]
    event_type: str
    query_text: Optional[str]
    response_text: Optional[str]
    classification: Optional[str]
    status: str
    ip_address: Optional[str]
    prev_hash: str
    current_hash: str


class ChainVerifyResult(BaseModel):
    total: int
    valid: bool
    first_invalid_id: Optional[int] = None
    message: str


# === Admin: update role ===
class UpdateRoleRequest(BaseModel):
    role: RoleEnum


class UpdateActiveRequest(BaseModel):
    is_active: bool
