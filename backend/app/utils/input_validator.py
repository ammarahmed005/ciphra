"""
Input Validation and Sanitization Utility — CIPHRA
Prevents integer overflow, XSS, and injection attacks via strict input validation.

Features:
  - Integer overflow protection with explicit bounds checking
  - String length enforcement
  - XSS prevention via HTML entity encoding
  - Type enforcement on all inputs
  - Numeric range validation
  - Safe field extractor for request payloads
"""

import html
import logging
import math
import re
from typing import Any, Optional

logger = logging.getLogger("ciphra.input_validator")


# ─── Integer Bounds ───────────────────────────────────────────────────────────

INT8_MIN,   INT8_MAX   = -128,                127
INT16_MIN,  INT16_MAX  = -32_768,             32_767
INT32_MIN,  INT32_MAX  = -2_147_483_648,      2_147_483_647
INT64_MIN,  INT64_MAX  = -9_223_372_036_854_775_808, 9_223_372_036_854_775_807

UINT8_MAX  = 0xFF
UINT16_MAX = 0xFFFF
UINT32_MAX = 0xFFFFFFFF
UINT64_MAX = 0xFFFFFFFFFFFFFFFF


# ─── String Limits ────────────────────────────────────────────────────────────

MAX_USERNAME_LENGTH   = 50
MAX_EMAIL_LENGTH      = 254       # RFC 5321
MAX_PASSWORD_LENGTH   = 128
MAX_MESSAGE_LENGTH    = 2_000     # chat messages
MAX_GENERIC_LENGTH    = 500


# ─── XSS Dangerous Patterns ──────────────────────────────────────────────────

XSS_PATTERNS = re.compile(
    r"(<script[\s\S]*?>[\s\S]*?</script>)"   # script tags
    r"|(<iframe[\s\S]*?>)"                    # iframes
    r"|(javascript\s*:)"                      # javascript: URIs
    r"|(on\w+\s*=)"                           # event handlers like onerror=
    r"|(<img[^>]+src\s*=\s*['\"]?\s*data:)"  # data: URIs in img
    r"|(document\s*\.\s*cookie)"             # cookie stealing
    r"|(window\s*\.\s*location)",            # redirect attacks
    re.IGNORECASE,
)


# ─── Integer Validators ───────────────────────────────────────────────────────

def validate_int(
    value: Any,
    min_val: int = INT32_MIN,
    max_val: int = INT32_MAX,
    field_name: str = "value",
) -> int:
    """
    Validate and parse an integer within explicit bounds.
    Prevents integer overflow and type confusion attacks.

    Args:
        value:      Raw input value (str, int, float accepted).
        min_val:    Minimum allowed value (inclusive).
        max_val:    Maximum allowed value (inclusive).
        field_name: Name of the field for error messages.

    Returns:
        Validated integer.

    Raises:
        ValueError with a safe message on failure.
    """
    if value is None:
        raise ValueError(f"'{field_name}' is required.")

    # Convert to int safely
    try:
        if isinstance(value, float):
            if not value.is_integer():
                raise ValueError(f"'{field_name}' must be a whole number, not a decimal.")
            if math.isnan(value) or math.isinf(value):
                raise ValueError(f"'{field_name}' must be a finite number.")
            int_val = int(value)
        elif isinstance(value, str):
            value = value.strip()
            if not value.lstrip("-").isdigit():
                raise ValueError(f"'{field_name}' must contain only digits.")
            int_val = int(value)
        elif isinstance(value, int) and not isinstance(value, bool):
            int_val = value
        else:
            raise ValueError(f"'{field_name}' must be an integer.")
    except (ValueError, OverflowError):
        raise ValueError(f"'{field_name}' is not a valid integer.")

    # Explicit bounds check — prevents overflow
    if not (min_val <= int_val <= max_val):
        raise ValueError(
            f"'{field_name}' must be between {min_val} and {max_val}. "
            f"Got: {int_val}."
        )

    return int_val


def validate_uint32(value: Any, field_name: str = "value") -> int:
    """Validate a 32-bit unsigned integer (0 to 4,294,967,295)."""
    return validate_int(value, min_val=0, max_val=UINT32_MAX, field_name=field_name)


def validate_uint16(value: Any, field_name: str = "value") -> int:
    """Validate a 16-bit unsigned integer (0 to 65,535)."""
    return validate_int(value, min_val=0, max_val=UINT16_MAX, field_name=field_name)


def validate_positive_int(value: Any, field_name: str = "value") -> int:
    """Validate a positive integer (>= 1)."""
    return validate_int(value, min_val=1, max_val=INT32_MAX, field_name=field_name)


def safe_add_uint32(x: int, y: int) -> int:
    """
    Safely add two uint32 values.
    Detects overflow before it occurs.

    Args:
        x: First operand (0 to UINT32_MAX).
        y: Second operand (0 to UINT32_MAX).

    Returns:
        Sum if within uint32 range.

    Raises:
        ValueError on overflow.
    """
    x = validate_uint32(x, "x")
    y = validate_uint32(y, "y")

    result = x + y
    if result > UINT32_MAX:
        logger.warning(
            "Integer overflow detected: %d + %d = %d (exceeds UINT32_MAX)",
            x, y, result,
        )
        raise ValueError(
            f"Integer overflow: {x} + {y} = {result} exceeds "
            f"the maximum 32-bit unsigned value ({UINT32_MAX})."
        )

    return result


# ─── String Validators ────────────────────────────────────────────────────────

def validate_string(
    value: Any,
    min_length: int = 1,
    max_length: int = MAX_GENERIC_LENGTH,
    field_name: str = "value",
    allow_empty: bool = False,
) -> str:
    """
    Validate a string input with length bounds.

    Args:
        value:       Raw input.
        min_length:  Minimum string length.
        max_length:  Maximum string length.
        field_name:  Field name for error messages.
        allow_empty: If True, empty strings are accepted.

    Returns:
        Stripped, validated string.

    Raises:
        ValueError on failure.
    """
    if value is None:
        if allow_empty:
            return ""
        raise ValueError(f"'{field_name}' is required.")

    if not isinstance(value, str):
        raise ValueError(f"'{field_name}' must be a string.")

    value = value.strip()

    if not allow_empty and len(value) < min_length:
        raise ValueError(
            f"'{field_name}' must be at least {min_length} character(s) long."
        )

    if len(value) > max_length:
        raise ValueError(
            f"'{field_name}' must not exceed {max_length} characters. "
            f"Got {len(value)}."
        )

    return value


def validate_username(value: Any) -> str:
    """
    Validate a username — alphanumeric, underscores, hyphens only.
    """
    username = validate_string(
        value,
        min_length=3,
        max_length=MAX_USERNAME_LENGTH,
        field_name="username",
    )
    if not re.match(r"^[a-zA-Z0-9_\-]+$", username):
        raise ValueError(
            "Username may only contain letters, numbers, underscores, and hyphens."
        )
    return username


def validate_email(value: Any) -> str:
    """
    Validate an email address format and length.
    """
    email = validate_string(
        value,
        min_length=5,
        max_length=MAX_EMAIL_LENGTH,
        field_name="email",
    )
    if not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email):
        raise ValueError("Invalid email address format.")
    return email.lower()


def validate_message(value: Any) -> str:
    """
    Validate a chat message — length limited, XSS checked.
    """
    message = validate_string(
        value,
        min_length=1,
        max_length=MAX_MESSAGE_LENGTH,
        field_name="message",
    )
    return sanitize_string(message)


# ─── XSS Sanitization ────────────────────────────────────────────────────────

def escape_html(value: str) -> str:
    """
    Escape HTML special characters to prevent XSS.
    Converts <, >, &, ", ' to safe HTML entities.

    Args:
        value: Raw string input.

    Returns:
        HTML-escaped string safe for rendering.
    """
    return html.escape(value, quote=True)


def sanitize_string(value: str) -> str:
    """
    Detect and neutralize XSS patterns in a string.
    Logs a warning if suspicious patterns are found.

    Args:
        value: Raw string input.

    Returns:
        HTML-escaped string with XSS patterns neutralized.
    """
    if XSS_PATTERNS.search(value):
        logger.warning(
            "XSS pattern detected in input — escaping: %r",
            value[:100],   # log only first 100 chars
        )

    # Always escape — defense in depth
    return escape_html(value)


def strip_null_bytes(value: str) -> str:
    """
    Remove null bytes from a string.
    Null bytes can bypass string validation in some contexts.
    """
    return value.replace("\x00", "").replace("\u0000", "")


# ─── Payload Validator ────────────────────────────────────────────────────────

class ValidationError(Exception):
    """Raised when input validation fails."""
    def __init__(self, field: str, message: str):
        self.field = field
        self.message = message
        super().__init__(f"{field}: {message}")


def validate_payload(payload: dict, schema: dict) -> dict:
    """
    Validate a request payload against a schema definition.

    Schema format:
        {
            "field_name": {
                "type":       "str" | "int" | "email" | "username",
                "required":   True | False,
                "min":        int (for int type: min value, for str: min length),
                "max":        int (for int type: max value, for str: max length),
                "allow_empty": True | False,
            }
        }

    Args:
        payload: Dict of raw input values.
        schema:  Validation schema.

    Returns:
        Dict of validated and sanitized values.

    Raises:
        ValidationError on first failed field.
    """
    result = {}

    for field, rules in schema.items():
        raw = payload.get(field)
        required = rules.get("required", True)
        field_type = rules.get("type", "str")

        if raw is None and not required:
            result[field] = rules.get("default", None)
            continue

        try:
            if field_type == "int":
                result[field] = validate_int(
                    raw,
                    min_val=rules.get("min", INT32_MIN),
                    max_val=rules.get("max", INT32_MAX),
                    field_name=field,
                )
            elif field_type == "uint32":
                result[field] = validate_uint32(raw, field_name=field)
            elif field_type == "email":
                result[field] = validate_email(raw)
            elif field_type == "username":
                result[field] = validate_username(raw)
            elif field_type == "str":
                result[field] = validate_string(
                    raw,
                    min_length=rules.get("min", 1),
                    max_length=rules.get("max", MAX_GENERIC_LENGTH),
                    field_name=field,
                    allow_empty=rules.get("allow_empty", False),
                )
            else:
                raise ValidationError(field, f"Unknown type '{field_type}' in schema.")

        except ValueError as e:
            raise ValidationError(field, str(e))

    return result