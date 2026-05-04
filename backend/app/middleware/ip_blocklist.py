"""
IP Blocklist Middleware — CIPHRA
Blocks requests from known malicious IPs before they reach any route.

Features:
  - Static blocklist loaded from config/environment
  - Dynamic blocklist that auto-expires entries after a TTL
  - CIDR range blocking (e.g. block entire subnets)
  - Audit logs every blocked request
  - Admin API to add/remove/list blocked IPs at runtime
"""

import ipaddress
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware

logger = logging.getLogger("ciphra.ip_blocklist")


# ─── Static blocklist ─────────────────────────────────────────────────────────
# Add known bad IPs or CIDR ranges here, or load from environment.
# Example: ["192.168.1.100", "10.0.0.0/8"]

STATIC_BLOCKLIST: list[str] = []


# ─── Dynamic blocklist ────────────────────────────────────────────────────────
# Populated at runtime via add_to_blocklist().
# Structure: { "ip_string": expiry_datetime | None }
# None means permanent block.

_dynamic_blocklist: dict[str, Optional[datetime]] = {}


# ─── Whitelist ────────────────────────────────────────────────────────────────
# IPs that are NEVER blocked (e.g. internal health checkers, admin IPs).

WHITELIST: list[str] = [
    "127.0.0.1",
    "::1",
]


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _parse_network(ip_or_cidr: str) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    """Parse an IP or CIDR string into a network object."""
    try:
        return ipaddress.ip_network(ip_or_cidr, strict=False)
    except ValueError:
        logger.warning("Invalid IP/CIDR in blocklist: %s", ip_or_cidr)
        return None


def _is_in_list(ip: str, ip_list: list[str]) -> bool:
    """Check if an IP matches any entry (exact or CIDR) in a list."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for entry in ip_list:
        network = _parse_network(entry)
        if network and addr in network:
            return True
    return False


def _purge_expired() -> None:
    """Remove expired dynamic blocklist entries."""
    now = datetime.now(timezone.utc)
    expired = [
        ip for ip, expiry in _dynamic_blocklist.items()
        if expiry is not None and now > expiry
    ]
    for ip in expired:
        del _dynamic_blocklist[ip]
        logger.info("IP %s removed from dynamic blocklist (TTL expired)", ip)


# ─── Public API ───────────────────────────────────────────────────────────────

def add_to_blocklist(ip: str, ttl_minutes: Optional[int] = None) -> None:
    """
    Add an IP to the dynamic blocklist.

    Args:
        ip:           The IP address to block.
        ttl_minutes:  How long to block it. None = permanent.
    """
    expiry = None
    if ttl_minutes is not None:
        expiry = datetime.now(timezone.utc) + timedelta(minutes=ttl_minutes)
    _dynamic_blocklist[ip] = expiry
    logger.warning(
        "IP %s added to dynamic blocklist. Expiry: %s",
        ip,
        expiry.isoformat() if expiry else "permanent",
    )


def remove_from_blocklist(ip: str) -> bool:
    """
    Remove an IP from the dynamic blocklist.

    Returns:
        True if the IP was in the list and removed, False otherwise.
    """
    if ip in _dynamic_blocklist:
        del _dynamic_blocklist[ip]
        logger.info("IP %s removed from dynamic blocklist", ip)
        return True
    return False


def list_blocklist() -> list[dict]:
    """
    Return all current dynamic blocklist entries with their expiry times.
    """
    _purge_expired()
    now = datetime.now(timezone.utc)
    return [
        {
            "ip": ip,
            "expiry": expiry.isoformat() if expiry else "permanent",
            "remaining_minutes": (
                int((expiry - now).total_seconds() / 60)
                if expiry else None
            ),
        }
        for ip, expiry in _dynamic_blocklist.items()
    ]


def is_blocked(ip: str) -> bool:
    """
    Check if an IP is currently blocked.
    Checks whitelist first, then static and dynamic blocklists.
    """
    # Never block whitelisted IPs
    if _is_in_list(ip, WHITELIST):
        return False

    # Check static blocklist
    if _is_in_list(ip, STATIC_BLOCKLIST):
        return True

    # Check dynamic blocklist (with expiry)
    _purge_expired()
    if ip in _dynamic_blocklist:
        expiry = _dynamic_blocklist[ip]
        if expiry is None or datetime.now(timezone.utc) < expiry:
            return True

    return False


# ─── Middleware ───────────────────────────────────────────────────────────────

class IPBlocklistMiddleware(BaseHTTPMiddleware):
    """
    Starlette middleware that blocks requests from blocklisted IPs.
    Attach to the FastAPI app in main.py.
    """

    async def dispatch(self, request: Request, call_next):
        # Extract real client IP (respect X-Forwarded-For from trusted proxy)
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            client_ip = forwarded_for.split(",")[0].strip()
        else:
            client_ip = request.client.host if request.client else "unknown"

        if is_blocked(client_ip):
            logger.warning(
                "Blocked request from IP %s to %s %s",
                client_ip,
                request.method,
                request.url.path,
            )
            return JSONResponse(
                status_code=403,
                content={"detail": "Access denied."},
            )

        return await call_next(request)