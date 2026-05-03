"""Small request-inspection helpers."""
from fastapi import Request


def client_ip(request: Request) -> str:
    """Extract the client IP, honoring X-Forwarded-For if behind a proxy."""
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def user_agent(request: Request) -> str:
    return (request.headers.get("user-agent") or "")[:512]
