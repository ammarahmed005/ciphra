"""FastAPI application entrypoint."""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

from app import __version__
from app.auth.password import hash_password
from app.config import settings
from app.database import SessionLocal, init_db
from app.models import RoleEnum, User
from app.routers import admin, audit, auth, chat, stats


logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL, logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("ciphra")


limiter = Limiter(
    # Rate limit by authenticated user when possible, else by IP
    key_func=lambda r: (
        r.headers.get("authorization", "") or get_remote_address(r)
    ),
    default_limits=[f"{settings.RATE_LIMIT_PER_MINUTE}/minute"],
)


# Maximum request body size to prevent DoS via giant payloads
MAX_REQUEST_BODY = 1 * 1024 * 1024  # 1 MiB


def _seed_default_users():
    """Create a default admin and one user per role on first run if none exist."""
    db = SessionLocal()
    try:
        if db.query(User).count() > 0:
            return
        # These passwords meet the new policy (10+ chars, 3+ char classes,
        # not in the common-password list). They MUST be rotated in production.
        defaults = [
            ("admin", "admin@example.com", "Adm!nP@ss2026", RoleEnum.ADMIN),
            ("manager", "manager@example.com", "Mgr!n@ger2026", RoleEnum.MANAGER),
            ("employee", "employee@example.com", "Emp!oyee@2026", RoleEnum.EMPLOYEE),
            ("guest", "guest@example.com", "Gue$t!Pass2026", RoleEnum.GUEST),
        ]
        for username, email, pwd, role in defaults:
            db.add(User(
                username=username,
                email=email,
                hashed_password=hash_password(pwd),
                role=role,
            ))
        db.commit()
        logger.warning(
            "Seeded default users. CHANGE THESE PASSWORDS BEFORE PRODUCTION. "
            "Credentials: admin/Adm!nP@ss2026, manager/Mgr!n@ger2026, "
            "employee/Emp!oyee@2026, guest/Gue$t!Pass2026"
        )
    finally:
        db.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting CIPHRA backend v%s", __version__)
    init_db()
    _seed_default_users()
    _apply_audit_append_only_trigger()
    logger.info("Startup complete. AI provider: %s", settings.AI_PROVIDER)
    yield
    logger.info("Shutting down.")


def _apply_audit_append_only_trigger():
    """
    Install Postgres triggers that REJECT updates/deletes on audit_logs at the
    DB level. This is defense-in-depth on top of the hash chain — the chain
    detects tampering, the trigger prevents it.

    No-op on non-Postgres databases (e.g. SQLite for tests).
    """
    if not settings.DATABASE_URL.startswith("postgresql"):
        return
    from sqlalchemy import text
    from app.database import engine
    sql = """
    CREATE OR REPLACE FUNCTION ciphra_audit_append_only()
    RETURNS TRIGGER AS $$
    BEGIN
        RAISE EXCEPTION 'audit_logs is append-only -- % operations are forbidden', TG_OP
            USING ERRCODE = 'insufficient_privilege';
    END;
    $$ LANGUAGE plpgsql;

    DROP TRIGGER IF EXISTS audit_append_only_update ON audit_logs;
    DROP TRIGGER IF EXISTS audit_append_only_delete ON audit_logs;

    CREATE TRIGGER audit_append_only_update
        BEFORE UPDATE ON audit_logs
        FOR EACH ROW EXECUTE FUNCTION ciphra_audit_append_only();
    CREATE TRIGGER audit_append_only_delete
        BEFORE DELETE ON audit_logs
        FOR EACH ROW EXECUTE FUNCTION ciphra_audit_append_only();
    """
    try:
        with engine.begin() as conn:
            conn.execute(text(sql))
        logger.info("Audit append-only triggers applied to Postgres.")
    except Exception as e:
        logger.warning("Could not apply audit triggers: %s", e)


app = FastAPI(
    title="CIPHRA — Secure RBAC Chatbot",
    description=(
        "Classified Information Protected via Hash-chained Role Access. "
        "An AI chatbot enforcing role-based access control, query sensitivity "
        "classification, prompt-injection defense, and tamper-evident audit logging."
    ),
    version=__version__,
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Body size limit middleware
@app.middleware("http")
async def body_size_guard(request: Request, call_next):
    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_REQUEST_BODY:
                return JSONResponse(
                    status_code=413,
                    content={"detail": "Request body too large"},
                )
        except ValueError:
            pass
    return await call_next(request)


# Security headers middleware — OWASP Secure Headers Project aligned
@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Strict-Transport-Security"] = (
        "max-age=31536000; includeSubDomains; preload"
    )
    response.headers["Permissions-Policy"] = (
        "geolocation=(), microphone=(), camera=(), "
        "payment=(), usb=(), magnetometer=(), gyroscope=()"
    )
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-site"
    response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
    # Content Security Policy — applies to API responses too as defense-in-depth
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self';"
    )
    # Remove fingerprinting headers if present
    if "Server" in response.headers:
        del response.headers["Server"]
    return response


# Global exception handler that never leaks internals
@app.exception_handler(Exception)
async def unhandled(request: Request, exc: Exception):
    logger.exception("Unhandled error on %s %s: %s", request.method, request.url.path, exc)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})


# Routers
app.include_router(auth.router)
app.include_router(chat.router)
app.include_router(admin.router)
app.include_router(audit.router)
app.include_router(stats.router)


@app.get("/api/health")
def health():
    return {"status": "ok", "version": __version__, "ai_provider": settings.AI_PROVIDER}


@app.get("/")
def root():
    return {
        "name": "CIPHRA",
        "tagline": "Classified Information Protected via Hash-chained Role Access",
        "version": __version__,
        "docs": "/docs",
        "health": "/api/health",
    }
