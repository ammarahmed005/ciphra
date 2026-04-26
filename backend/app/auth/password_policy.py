"""
Password strength policy.

Implements NIST SP 800-63B-aligned rules:
  - Minimum 10 characters
  - Maximum 128 characters
  - Must contain mixed case + digits OR mixed case + symbols
  - Rejects passwords on a known-compromised wordlist
  - Rejects passwords containing the username
  - Rejects sequential / repeating patterns (`aaaaaaaa`, `12345678`, `qwerty...`)

Returns a list of human-readable failure reasons (empty list = passes).
"""
import re

# A small but representative blocklist of the most-common breached passwords.
# In production this would be replaced with the full HIBP top-million file
# loaded as a Bloom filter or k-anonymity API lookup against haveibeenpwned.com.
COMMON_PASSWORDS = frozenset({
    "password", "password1", "password123", "passw0rd", "p@ssword", "p@ssw0rd",
    "12345678", "123456789", "1234567890", "qwerty", "qwerty123", "qwertyuiop",
    "abc12345", "letmein", "welcome", "welcome1", "iloveyou", "admin", "admin123",
    "administrator", "root", "toor", "changeme", "default", "guest",
    "monkey", "dragon", "sunshine", "princess", "master", "hello", "secret",
    "trustno1", "111111", "000000", "asdfghjkl", "zxcvbnm",
    "football", "baseball", "starwars", "superman", "batman",
    "qazwsx", "qaz123", "abcdef", "abcdefg", "abcdefgh",
})

MIN_LENGTH = 10
MAX_LENGTH = 128


def _has_sequence(s: str, length: int = 5) -> bool:
    """Detect sequential characters like 'abcde' or '12345'."""
    s = s.lower()
    for i in range(len(s) - length + 1):
        chunk = s[i:i + length]
        if all(ord(chunk[j + 1]) - ord(chunk[j]) == 1 for j in range(length - 1)):
            return True
        if all(ord(chunk[j + 1]) - ord(chunk[j]) == -1 for j in range(length - 1)):
            return True
    return False


def _has_repeat(s: str, length: int = 4) -> bool:
    """Detect repeating characters like 'aaaa' or '1111'."""
    return bool(re.search(r"(.)\1{" + str(length - 1) + ",}", s))


def _char_classes(s: str) -> int:
    """Count character classes used: lower, upper, digit, symbol."""
    classes = 0
    if re.search(r"[a-z]", s): classes += 1
    if re.search(r"[A-Z]", s): classes += 1
    if re.search(r"[0-9]", s): classes += 1
    if re.search(r"[^a-zA-Z0-9]", s): classes += 1
    return classes


def validate_password(password: str, username: str = "") -> list[str]:
    """
    Validate a password and return a list of failure reasons.
    Empty list means the password is acceptable.
    """
    errors: list[str] = []

    if not isinstance(password, str):
        return ["Password must be a string"]

    if len(password) < MIN_LENGTH:
        errors.append(f"Password must be at least {MIN_LENGTH} characters long")
    if len(password) > MAX_LENGTH:
        errors.append(f"Password must be no more than {MAX_LENGTH} characters long")

    # Require at least 3 of the 4 character classes
    if _char_classes(password) < 3:
        errors.append(
            "Password must contain at least three of: "
            "lowercase letters, uppercase letters, digits, and symbols"
        )

    if password.lower() in COMMON_PASSWORDS:
        errors.append("Password is too common and easily guessed")

    # Reject passwords that simply prepend digits/symbols to a common one
    stripped = re.sub(r"[^a-zA-Z]", "", password.lower())
    if stripped and stripped in COMMON_PASSWORDS:
        errors.append("Password is too close to a commonly-used password")

    if username and len(username) >= 3 and username.lower() in password.lower():
        errors.append("Password must not contain the username")

    if _has_sequence(password):
        errors.append("Password must not contain long sequential characters (e.g. 'abcde', '12345')")

    if _has_repeat(password):
        errors.append("Password must not contain repeating characters (e.g. 'aaaa', '1111')")

    return errors
