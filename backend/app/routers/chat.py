"""
Chat endpoint — the heart of the RBAC enforcement.

Request flow (matching the proposal's sequence diagram):
  1. validateJWT   → handled by get_current_user dependency
  2. resolveRole   → user.role
  3. classify      → classifier.classify_query
  4. checkPermission → RBACEngine.is_permitted
  5. if denied: logEvent(DENIED) and return the denial
  6. if permitted: AI generate → response filter → logEvent(ALLOWED) → return
"""
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.audit.logger import record_event
from app.auth.dependencies import get_current_user
from app.chatbot.ai_engine import ai_engine
from app.chatbot.classifier import (
    classify_query, detect_prompt_injection, sanitize_input,
)
from app.chatbot.filter import filter_response
from app.database import get_db
from app.models import SensitivityEnum, User
from app.rbac.policy import RBACEngine
from app.routers._utils import client_ip, user_agent
from app.schemas import ChatRequest, ChatResponse


router = APIRouter(prefix="/api/chat", tags=["chat"])


@router.post("", response_model=ChatResponse)
async def chat(
    payload: ChatRequest,
    request: Request,
    db: Annotated[Session, Depends(get_db)],
    current_user: Annotated[User, Depends(get_current_user)],
):
    ip = client_ip(request)
    ua = user_agent(request)

    # 1. Sanitize
    cleaned = sanitize_input(payload.message)

    # 2. Classify
    classification = classify_query(cleaned)

    # 3. Check for prompt injection — block outright
    if detect_prompt_injection(cleaned):
        record_event(
            db,
            event_type="PROMPT_INJECTION_BLOCKED",
            status="DENIED",
            user_id=current_user.id,
            username=current_user.username,
            role=current_user.role.value,
            query_text=cleaned,
            classification=classification.value,
            ip_address=ip,
            user_agent=ua,
        )
        return ChatResponse(
            status="denied",
            classification=classification,
            reply=(
                "Your message was flagged as a potential prompt-injection attempt "
                "and has been blocked. This incident has been logged."
            ),
            reason="prompt_injection_detected",
        )

    # 4. RBAC check
    if not RBACEngine.is_permitted(current_user.role, classification):
        reason = RBACEngine.deny_reason(current_user.role, classification)
        record_event(
            db,
            event_type="QUERY_DENIED",
            status="DENIED",
            user_id=current_user.id,
            username=current_user.username,
            role=current_user.role.value,
            query_text=cleaned,
            response_text=reason,
            classification=classification.value,
            ip_address=ip,
            user_agent=ua,
        )
        return ChatResponse(
            status="denied",
            classification=classification,
            reply=reason,
            reason="insufficient_role",
        )

    # 5. Generate
    raw_reply = await ai_engine.generate(cleaned, current_user.role)

    # 6. Filter response (universal redactions + role-scoped)
    final_reply = filter_response(raw_reply, current_user.role)

    # 7. Log
    record_event(
        db,
        event_type="QUERY",
        status="ALLOWED",
        user_id=current_user.id,
        username=current_user.username,
        role=current_user.role.value,
        query_text=cleaned,
        response_text=final_reply,
        classification=classification.value,
        ip_address=ip,
        user_agent=ua,
    )

    return ChatResponse(
        status="allowed",
        classification=classification,
        reply=final_reply,
    )
