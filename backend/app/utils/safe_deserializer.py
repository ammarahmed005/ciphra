"""
Safe Deserialization Utility — CIPHRA
Prevents deserialization attacks by enforcing JSON-only data exchange.

Features:
  - JSON-only parsing (no pickle, no yaml.load, no eval)
  - Schema validation on parsed data
  - Size limits to prevent memory exhaustion
  - Type enforcement on parsed values
  - Deep nesting protection
  - Audit logs malformed or oversized payloads
"""

import json
import logging
from typing import Any, Optional

logger = logging.getLogger("ciphra.safe_deserializer")


# ─── Constants ────────────────────────────────────────────────────────────────

MAX_PAYLOAD_SIZE = 1 * 1024 * 1024     # 1 MiB — matches backend body limit
MAX_STRING_LENGTH = 10_000             # max chars in any single string value
MAX_ARRAY_LENGTH = 1_000               # max items in any array
MAX_OBJECT_KEYS = 100                  # max keys in any object
MAX_NESTING_DEPTH = 10                 # max nested levels


# ─── Depth checker ────────────────────────────────────────────────────────────

def _check_depth(obj: Any, current_depth: int = 0) -> None:
    """
    Recursively check nesting depth of a parsed JSON object.
    Raises ValueError if depth exceeds MAX_NESTING_DEPTH.
    """
    if current_depth > MAX_NESTING_DEPTH:
        raise ValueError(
            f"JSON nesting depth exceeds maximum allowed ({MAX_NESTING_DEPTH})."
        )

    if isinstance(obj, dict):
        for value in obj.values():
            _check_depth(value, current_depth + 1)
    elif isinstance(obj, list):
        for item in obj:
            _check_depth(item, current_depth + 1)


# ─── Value sanitizer ──────────────────────────────────────────────────────────

def _sanitize_value(value: Any, path: str = "root") -> Any:
    """
    Recursively validate and sanitize a parsed JSON value.
    Enforces size limits on strings, arrays, and objects.

    Args:
        value: The parsed JSON value.
        path:  Dot-notation path for error messages.

    Returns:
        The sanitized value.

    Raises:
        ValueError if any limit is exceeded.
    """
    if isinstance(value, str):
        if len(value) > MAX_STRING_LENGTH:
            raise ValueError(
                f"String at '{path}' exceeds max length "
                f"({len(value)} > {MAX_STRING_LENGTH})."
            )
        return value

    elif isinstance(value, dict):
        if len(value) > MAX_OBJECT_KEYS:
            raise ValueError(
                f"Object at '{path}' has too many keys "
                f"({len(value)} > {MAX_OBJECT_KEYS})."
            )
        return {
            k: _sanitize_value(v, path=f"{path}.{k}")
            for k, v in value.items()
            if isinstance(k, str)   # silently drop non-string keys
        }

    elif isinstance(value, list):
        if len(value) > MAX_ARRAY_LENGTH:
            raise ValueError(
                f"Array at '{path}' has too many items "
                f"({len(value)} > {MAX_ARRAY_LENGTH})."
            )
        return [
            _sanitize_value(item, path=f"{path}[{i}]")
            for i, item in enumerate(value)
        ]

    elif isinstance(value, (int, float, bool, type(None))):
        return value

    else:
        # Unexpected type — reject it
        raise ValueError(f"Unsupported type '{type(value).__name__}' at '{path}'.")


# ─── Core Parser ──────────────────────────────────────────────────────────────

def safe_json_loads(
    raw: str | bytes,
    max_size: int = MAX_PAYLOAD_SIZE,
    fallback: Optional[Any] = None,
) -> Any:
    """
    Safely parse a JSON string or bytes with full validation.

    Security guarantees:
      - Uses json.loads() — NOT pickle, eval, or yaml.load
      - Size check before parsing (prevents memory exhaustion)
      - Nesting depth check (prevents stack overflow)
      - Per-field size limits (prevents oversized strings/arrays)

    Args:
        raw:      Raw JSON string or bytes to parse.
        max_size: Maximum allowed payload size in bytes.
        fallback: Value to return on parse failure (default: None).

    Returns:
        Parsed and sanitized Python object, or fallback on failure.

    Raises:
        ValueError with a safe message on validation failure.
    """
    if not raw:
        return fallback if fallback is not None else {}

    # Size check before parsing
    raw_bytes = raw.encode("utf-8") if isinstance(raw, str) else raw
    if len(raw_bytes) > max_size:
        logger.warning(
            "Oversized JSON payload rejected: %d bytes (max %d).",
            len(raw_bytes), max_size,
        )
        raise ValueError(
            f"Payload too large ({len(raw_bytes)} bytes). "
            f"Maximum allowed is {max_size} bytes."
        )

    # Parse JSON safely — never use pickle or eval
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as e:
        logger.warning("JSON parse error: %s", e)
        if fallback is not None:
            return fallback
        raise ValueError(f"Invalid JSON: {e.msg}")

    # Depth check
    try:
        _check_depth(parsed)
    except ValueError as e:
        logger.warning("JSON depth limit exceeded: %s", e)
        raise

    # Sanitize all values
    try:
        sanitized = _sanitize_value(parsed)
    except ValueError as e:
        logger.warning("JSON value validation failed: %s", e)
        raise

    return sanitized


def safe_json_dumps(obj: Any, pretty: bool = False) -> str:
    """
    Safely serialize a Python object to JSON string.

    Args:
        obj:    The object to serialize.
        pretty: If True, indent output for readability.

    Returns:
        JSON string.

    Raises:
        ValueError if the object is not JSON serializable.
    """
    try:
        return json.dumps(
            obj,
            indent=2 if pretty else None,
            ensure_ascii=True,          # escape non-ASCII for safety
            allow_nan=False,            # NaN/Infinity are not valid JSON
        )
    except (TypeError, ValueError) as e:
        logger.error("JSON serialization failed: %s", e)
        raise ValueError(f"Object is not JSON serializable: {e}")


# ─── Request body parser ──────────────────────────────────────────────────────

def parse_request_body(
    body: str | bytes,
    required_keys: Optional[list[str]] = None,
    allowed_keys: Optional[list[str]] = None,
) -> dict:
    """
    Parse and validate a JSON request body from an API endpoint.

    Args:
        body:          Raw request body string or bytes.
        required_keys: Keys that must be present in the parsed object.
        allowed_keys:  If provided, reject any keys not in this list.

    Returns:
        Validated dict.

    Raises:
        ValueError with a safe message on any validation failure.
    """
    parsed = safe_json_loads(body, fallback=None)

    if parsed is None:
        raise ValueError("Request body could not be parsed as JSON.")

    if not isinstance(parsed, dict):
        raise ValueError("Request body must be a JSON object.")

    # Check required keys
    if required_keys:
        missing = [k for k in required_keys if k not in parsed]
        if missing:
            raise ValueError(f"Missing required fields: {', '.join(missing)}")

    # Strip unknown keys if allowlist provided
    if allowed_keys:
        unknown = [k for k in parsed if k not in allowed_keys]
        if unknown:
            logger.warning("Stripping unknown keys from request: %s", unknown)
            parsed = {k: v for k, v in parsed.items() if k in allowed_keys}

    return parsed


# ─── NEVER USE THESE ─────────────────────────────────────────────────────────

def _pickle_is_forbidden(*args, **kwargs):
    """
    Pickle deserialization is NEVER safe with untrusted data.
    This function exists to make that explicit in code.
    """
    raise RuntimeError(
        "pickle.loads() is forbidden in CIPHRA. "
        "Use safe_json_loads() instead. "
        "Pickle can execute arbitrary code during deserialization."
    )


def _eval_is_forbidden(*args, **kwargs):
    """eval() on user input is never safe."""
    raise RuntimeError(
        "eval() is forbidden in CIPHRA. "
        "Use safe_json_loads() instead."
    )