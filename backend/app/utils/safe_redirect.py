"""
Safe Redirect Utility — CIPHRA
Prevents open redirect attacks by validating URLs against an allowlist.

Features:
  - Allowlist-based URL validation
  - Relative URL support (always safe)
  - Scheme enforcement (http/https only)
  - Subdomain validation
  - Safe fallback for invalid URLs
  - Audit logs every blocked redirect attempt
  - Ready for OAuth, email verification, password reset flows
"""

import logging
from urllib.parse import urlparse, urljoin
from typing import Optional

logger = logging.getLogger("ciphra.safe_redirect")


# ─── Allowed Hosts ────────────────────────────────────────────────────────────
# Add your production domain here when deploying.
# Format: "hostname:port" or just "hostname" for standard ports.

ALLOWED_HOSTS = {
    "localhost:5173",           # Vite dev server
    "localhost:3000",           # Alternative dev port
    "localhost:8000",           # Backend dev server
    "localhost:80",             # Nginx
    "127.0.0.1:5173",
    "127.0.0.1:3000",
    "127.0.0.1:8000",
}

# Allowed URL schemes — never allow javascript: or data: URIs
ALLOWED_SCHEMES = {"http", "https"}

# Safe fallback when redirect URL is invalid
SAFE_FALLBACK = "/"

# Maximum URL length to prevent buffer overflow attempts
MAX_URL_LENGTH = 2048


# ─── Core Validator ───────────────────────────────────────────────────────────

def is_safe_url(url: str, allowed_hosts: Optional[set] = None) -> bool:
    """
    Validate a redirect URL against an allowlist.

    Security rules:
      - Empty URLs are safe (redirect to fallback)
      - Relative URLs are always safe (no host = no external redirect)
      - Absolute URLs must use http/https scheme only
      - Absolute URLs must have host in the allowlist
      - javascript:, data:, vbscript: URIs are always rejected
      - Excessively long URLs are rejected

    Args:
        url:           The URL to validate.
        allowed_hosts: Override the default ALLOWED_HOSTS set.

    Returns:
        True if the URL is safe to redirect to, False otherwise.
    """
    if not url or not isinstance(url, str):
        return False

    # Length check — prevent buffer overflow attempts
    if len(url) > MAX_URL_LENGTH:
        logger.warning("Redirect URL too long (%d chars) — blocked.", len(url))
        return False

    # Strip whitespace and null bytes
    url = url.strip().replace("\x00", "")

    # Block javascript: and data: URIs immediately
    # These can execute code even without a netloc
    lower_url = url.lower().lstrip()
    for dangerous in ("javascript:", "data:", "vbscript:", "file:", "blob:"):
        if lower_url.startswith(dangerous):
            logger.warning(
                "Dangerous URI scheme blocked in redirect: %r", url[:50]
            )
            return False

    try:
        parsed = urlparse(url)
    except Exception:
        logger.warning("Failed to parse redirect URL: %r", url[:50])
        return False

    # Relative URLs (no netloc) are always safe
    # e.g. "/dashboard", "?tab=settings", "../profile"
    if not parsed.netloc:
        # But reject protocol-relative URLs like //evil.com
        if url.startswith("//"):
            logger.warning(
                "Protocol-relative URL blocked: %r", url[:50]
            )
            return False
        return True

    # Absolute URL — must use allowed scheme
    if parsed.scheme not in ALLOWED_SCHEMES:
        logger.warning(
            "Disallowed scheme in redirect URL: %r (scheme=%s)",
            url[:50], parsed.scheme,
        )
        return False

    # Normalise host — include port if non-standard
    host = parsed.hostname or ""
    port = parsed.port

    # Build normalised netloc for allowlist check
    if port:
        netloc_check = f"{host}:{port}"
    else:
        # Standard ports — check both with and without port
        netloc_check = host

    hosts = allowed_hosts if allowed_hosts is not None else ALLOWED_HOSTS

    # Check both "host" and "host:port" forms
    if netloc_check not in hosts and host not in hosts:
        logger.warning(
            "Redirect to non-allowlisted host blocked: %r (host=%s)",
            url[:50], netloc_check,
        )
        return False

    return True


# ─── Safe Redirect Helper ─────────────────────────────────────────────────────

def get_safe_redirect_url(
    url: Optional[str],
    fallback: str = SAFE_FALLBACK,
    allowed_hosts: Optional[set] = None,
) -> str:
    """
    Return a safe redirect URL, falling back to a default if invalid.

    Args:
        url:           The requested redirect URL (e.g. from ?next= param).
        fallback:      URL to use if validation fails (default: "/").
        allowed_hosts: Override the default ALLOWED_HOSTS set.

    Returns:
        A validated safe URL string.
    """
    if not url:
        return fallback

    if is_safe_url(url, allowed_hosts=allowed_hosts):
        logger.debug("Redirect URL validated as safe: %r", url[:50])
        return url

    logger.warning(
        "Unsafe redirect URL rejected, falling back to '%s': %r",
        fallback, url[:50],
    )
    return fallback


def get_next_url(
    next_param: Optional[str],
    default: str = "/",
) -> str:
    """
    Safely extract and validate a ?next= redirect parameter.
    Use this in login, OAuth callback, and email verification routes.

    Args:
        next_param: Raw value from request query parameter.
        default:    Safe default if next_param is invalid.

    Returns:
        Validated redirect URL.

    Example:
        @router.post("/api/auth/login")
        def login(request: Request, ...):
            next_url = get_next_url(request.query_params.get("next"))
            # ... authenticate user ...
            return RedirectResponse(url=next_url)
    """
    return get_safe_redirect_url(next_param, fallback=default)


# ─── Allowlist Management ─────────────────────────────────────────────────────

def add_allowed_host(host: str) -> None:
    """
    Dynamically add a host to the allowlist at runtime.
    Use this to add your production domain from environment config.

    Args:
        host: Hostname with optional port e.g. "example.com" or "app.example.com:443"
    """
    ALLOWED_HOSTS.add(host.lower().strip())
    logger.info("Added host to redirect allowlist: %s", host)


def remove_allowed_host(host: str) -> None:
    """
    Remove a host from the allowlist.

    Args:
        host: Hostname to remove.
    """
    ALLOWED_HOSTS.discard(host.lower().strip())
    logger.info("Removed host from redirect allowlist: %s", host)


def get_allowed_hosts() -> set:
    """
    Return the current set of allowed redirect hosts.

    Returns:
        Copy of the ALLOWED_HOSTS set.
    """
    return ALLOWED_HOSTS.copy()


# ─── FastAPI Route Example ────────────────────────────────────────────────────

"""
HOW TO USE IN A FASTAPI ROUTE:

from fastapi import APIRouter, Request
from fastapi.responses import RedirectResponse
from app.utils.safe_redirect import get_next_url

router = APIRouter()

@router.get("/redirect")
def safe_redirect(next: str = "/", request: Request = None):
    safe_url = get_next_url(next)
    return RedirectResponse(url=safe_url)

@router.post("/api/auth/login")
def login(request: Request, next: str = "/", ...):
    # ... authenticate user ...
    safe_url = get_next_url(next)
    return RedirectResponse(url=safe_url, status_code=302)
"""