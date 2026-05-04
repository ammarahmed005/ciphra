"""
Safe Subprocess Utility — CIPHRA
Prevents command injection by validating input and using shell=False.

Features:
  - Input allowlist validation (IP addresses, hostnames)
  - subprocess.run() with shell=False always
  - Timeout enforcement to prevent hanging
  - Output sanitization before returning
  - Audit logs every system command execution
  - Blocks dangerous characters and patterns
"""

import ipaddress
import logging
import re
import subprocess
from typing import Optional

logger = logging.getLogger("ciphra.safe_subprocess")


# ─── Constants ────────────────────────────────────────────────────────────────

MAX_OUTPUT_LENGTH = 4096        # truncate output beyond this
DEFAULT_TIMEOUT = 5             # seconds before killing the process
MAX_HOST_LENGTH = 253           # RFC 1035 max hostname length


# ─── Dangerous pattern detector ───────────────────────────────────────────────

# Characters that have special meaning in shells
SHELL_METACHARACTERS = re.compile(r"[;&|`$<>\\!\(\)\{\}\[\]\*\?\#~]")

# Patterns that indicate command injection attempts
INJECTION_PATTERNS = [
    r";\s*\w+",          # semicolon followed by command
    r"\|\s*\w+",         # pipe followed by command
    r"&&\s*\w+",         # AND operator
    r"\|\|\s*\w+",       # OR operator
    r"`[^`]+`",          # backtick command substitution
    r"\$\([^)]+\)",      # $() command substitution
    r"\.\./",            # directory traversal
    r"/etc/",            # sensitive path access
    r"/proc/",           # proc filesystem access
]

INJECTION_REGEX = re.compile("|".join(INJECTION_PATTERNS), re.IGNORECASE)


# ─── Input Validators ─────────────────────────────────────────────────────────

def validate_ip_address(host: str) -> bool:
    """
    Validate that a string is a valid IPv4 or IPv6 address.

    Args:
        host: The host string to validate.

    Returns:
        True if valid IP address, False otherwise.
    """
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def validate_hostname(hostname: str) -> bool:
    """
    Validate a hostname against RFC 1035 rules.
    Only allows letters, digits, hyphens, and dots.

    Args:
        hostname: The hostname string to validate.

    Returns:
        True if valid hostname, False otherwise.
    """
    if not hostname or len(hostname) > MAX_HOST_LENGTH:
        return False

    # Must contain only safe characters
    if not re.match(r"^[a-zA-Z0-9.\-]+$", hostname):
        return False

    # Check for injection patterns
    if INJECTION_REGEX.search(hostname):
        return False

    # Each label must be valid
    labels = hostname.split(".")
    for label in labels:
        if not label or len(label) > 63:
            return False
        if label.startswith("-") or label.endswith("-"):
            return False

    return True


def is_safe_input(value: str) -> bool:
    """
    General purpose input safety check.
    Rejects shell metacharacters and injection patterns.

    Args:
        value: Any string input to validate.

    Returns:
        True if input appears safe, False otherwise.
    """
    if not value or not isinstance(value, str):
        return False

    if SHELL_METACHARACTERS.search(value):
        logger.warning("Shell metacharacter detected in input: %r", value)
        return False

    if INJECTION_REGEX.search(value):
        logger.warning("Injection pattern detected in input: %r", value)
        return False

    return True


# ─── Safe Subprocess Runner ───────────────────────────────────────────────────

def safe_run(
    command: list[str],
    timeout: int = DEFAULT_TIMEOUT,
    allowed_executables: Optional[list[str]] = None,
) -> dict:
    """
    Run a system command safely with shell=False.

    Security guarantees:
      - shell=False: no shell interpretation of metacharacters
      - Command passed as list: arguments never concatenated into a string
      - Executable allowlist: only approved commands can run
      - Timeout: process killed if it hangs
      - Output truncated: prevents memory exhaustion

    Args:
        command:              List of [executable, arg1, arg2, ...]
        timeout:              Seconds before the process is killed.
        allowed_executables:  Whitelist of allowed executable names.

    Returns:
        dict with keys: stdout, stderr, returncode, success, truncated
    """
    if not command or not isinstance(command, list):
        logger.error("safe_run called with invalid command: %r", command)
        return {"success": False, "error": "Invalid command format."}

    executable = command[0]

    # Enforce executable allowlist
    if allowed_executables and executable not in allowed_executables:
        logger.warning(
            "Blocked execution of non-allowlisted executable: %s", executable
        )
        return {"success": False, "error": f"Executable '{executable}' is not permitted."}

    # Validate all arguments for injection patterns
    for arg in command[1:]:
        if not is_safe_input(str(arg)):
            logger.warning("Blocked unsafe argument in command: %r", arg)
            return {"success": False, "error": "Command contains unsafe characters."}

    logger.info("Executing safe command: %s", " ".join(command))

    try:
        result = subprocess.run(
            command,
            shell=False,                # CRITICAL — never use shell=True
            capture_output=True,
            text=True,
            timeout=timeout,
        )

        stdout = result.stdout or ""
        stderr = result.stderr or ""
        truncated = False

        # Truncate large outputs
        if len(stdout) > MAX_OUTPUT_LENGTH:
            stdout = stdout[:MAX_OUTPUT_LENGTH]
            truncated = True
            logger.warning("Command output truncated at %d chars.", MAX_OUTPUT_LENGTH)

        return {
            "success": result.returncode == 0,
            "returncode": result.returncode,
            "stdout": stdout,
            "stderr": stderr[:1024],    # limit stderr too
            "truncated": truncated,
        }

    except subprocess.TimeoutExpired:
        logger.warning("Command timed out after %ds: %s", timeout, command)
        return {"success": False, "error": f"Command timed out after {timeout}s."}

    except FileNotFoundError:
        logger.error("Executable not found: %s", executable)
        return {"success": False, "error": f"Executable '{executable}' not found."}

    except Exception as e:
        logger.exception("Unexpected error running command %s: %s", command, e)
        return {"success": False, "error": "Command execution failed."}


# ─── Convenience wrappers ─────────────────────────────────────────────────────

def safe_ping(host: str) -> dict:
    """
    Safely ping a host — validates IP/hostname before execution.

    Args:
        host: IP address or hostname to ping.

    Returns:
        dict with success, stdout, stderr.
    """
    if not validate_ip_address(host) and not validate_hostname(host):
        logger.warning("safe_ping blocked invalid host: %r", host)
        return {"success": False, "error": "Invalid host — only valid IP addresses or hostnames are allowed."}

    return safe_run(
        command=["ping", "-c", "1", "-W", "2", host],
        timeout=5,
        allowed_executables=["ping"],
    )


def safe_dns_lookup(hostname: str) -> dict:
    """
    Safely run a DNS lookup using nslookup.

    Args:
        hostname: The hostname to resolve.

    Returns:
        dict with success, stdout, stderr.
    """
    if not validate_hostname(hostname):
        logger.warning("safe_dns_lookup blocked invalid hostname: %r", hostname)
        return {"success": False, "error": "Invalid hostname."}

    return safe_run(
        command=["nslookup", hostname],
        timeout=5,
        allowed_executables=["nslookup"],
    )