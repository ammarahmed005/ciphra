"""
Password Strength Checker Utility — CIPHRA
Evaluates password strength and returns a score with detailed feedback.

Features:
  - Scoring system (0-100) with strength label
  - Checks for length, complexity, entropy
  - Detects common patterns (keyboard walks, repeated chars, sequences)
  - Integrates with CIPHRA's existing password policy
  - Returns actionable feedback messages
"""

import math
import re
import string
from dataclasses import dataclass, field


# ─── Common weak passwords ────────────────────────────────────────────────────

COMMON_PASSWORDS = {
    "password", "password123", "123456", "12345678", "qwerty",
    "abc123", "monkey", "master", "letmein", "dragon", "111111",
    "baseball", "iloveyou", "trustno1", "sunshine", "princess",
    "welcome", "shadow", "superman", "michael", "football",
    "admin", "admin123", "root", "toor", "pass", "test",
    "guest", "login", "changeme", "secret", "pass123",
}

# ─── Keyboard walk patterns ───────────────────────────────────────────────────

KEYBOARD_WALKS = [
    "qwerty", "qwertyuiop", "asdfgh", "asdfghjkl",
    "zxcvbn", "zxcvbnm", "1234567890", "0987654321",
    "qazwsx", "wsxedc", "edcrfv", "rfvtgb",
]


# ─── Result dataclass ─────────────────────────────────────────────────────────

@dataclass
class StrengthResult:
    score: int                        # 0-100
    label: str                        # Very Weak / Weak / Fair / Strong / Very Strong
    entropy: float                    # bits of entropy
    feedback: list[str] = field(default_factory=list)   # improvement tips
    penalties: list[str] = field(default_factory=list)  # what hurt the score
    bonuses: list[str] = field(default_factory=list)    # what helped the score

    @property
    def is_acceptable(self) -> bool:
        """True if score is at least Fair (>= 50)."""
        return self.score >= 50

    def to_dict(self) -> dict:
        return {
            "score": self.score,
            "label": self.label,
            "entropy": round(self.entropy, 2),
            "is_acceptable": self.is_acceptable,
            "feedback": self.feedback,
            "penalties": self.penalties,
            "bonuses": self.bonuses,
        }


# ─── Entropy calculator ───────────────────────────────────────────────────────

def _calculate_entropy(password: str) -> float:
    """
    Calculate Shannon entropy of the password.
    Higher entropy = more unpredictable = stronger password.
    """
    if not password:
        return 0.0

    # Character pool size based on what character classes are used
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"\d", password):
        pool += 10
    if re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?`~]", password):
        pool += 32

    if pool == 0:
        return 0.0

    return len(password) * math.log2(pool)


# ─── Pattern detectors ────────────────────────────────────────────────────────

def _has_keyboard_walk(password: str) -> bool:
    pw = password.lower()
    return any(walk in pw for walk in KEYBOARD_WALKS)


def _has_repeated_chars(password: str) -> bool:
    """Detect 3+ consecutive repeated characters e.g. 'aaa', '111'."""
    return bool(re.search(r"(.)\1{2,}", password))


def _has_sequential_chars(password: str) -> bool:
    """Detect sequential runs e.g. 'abcd', '1234'."""
    for i in range(len(password) - 2):
        a, b, c = ord(password[i]), ord(password[i+1]), ord(password[i+2])
        if b - a == 1 and c - b == 1:
            return True
        if a - b == 1 and b - c == 1:
            return True
    return False


def _is_common_password(password: str) -> bool:
    return password.lower() in COMMON_PASSWORDS


def _has_only_one_char_class(password: str) -> bool:
    classes = [
        bool(re.search(r"[a-z]", password)),
        bool(re.search(r"[A-Z]", password)),
        bool(re.search(r"\d", password)),
        bool(re.search(r"[^a-zA-Z0-9]", password)),
    ]
    return sum(classes) <= 1


def _has_username_in_password(password: str, username: str) -> bool:
    if not username:
        return False
    return username.lower() in password.lower()


# ─── Scorer ───────────────────────────────────────────────────────────────────

def _label_from_score(score: int) -> str:
    if score < 20:
        return "Very Weak"
    elif score < 40:
        return "Weak"
    elif score < 60:
        return "Fair"
    elif score < 80:
        return "Strong"
    return "Very Strong"


def check_strength(password: str, username: str = "") -> StrengthResult:
    """
    Evaluate password strength and return a detailed StrengthResult.

    Args:
        password: The password to evaluate.
        username: Optional — used to detect username-in-password patterns.

    Returns:
        StrengthResult with score (0-100), label, entropy, and feedback.
    """
    score = 0
    feedback = []
    penalties = []
    bonuses = []

    if not password:
        return StrengthResult(
            score=0,
            label="Very Weak",
            entropy=0.0,
            feedback=["Password cannot be empty."],
        )

    entropy = _calculate_entropy(password)

    # ── Length scoring ────────────────────────────────────────────────────────
    length = len(password)
    if length >= 20:
        score += 30
        bonuses.append("Excellent length (20+ characters)")
    elif length >= 16:
        score += 25
        bonuses.append("Great length (16+ characters)")
    elif length >= 12:
        score += 20
        bonuses.append("Good length (12+ characters)")
    elif length >= 10:
        score += 10
    elif length >= 8:
        score += 5
    else:
        score -= 10
        penalties.append("Too short (minimum 8 characters)")
        feedback.append("Use at least 8 characters, ideally 12 or more.")

    # ── Character class scoring ───────────────────────────────────────────────
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"\d", password))
    has_special = bool(re.search(r"[^a-zA-Z0-9]", password))

    char_classes = sum([has_lower, has_upper, has_digit, has_special])

    if char_classes == 4:
        score += 25
        bonuses.append("Uses all character classes (upper, lower, digits, symbols)")
    elif char_classes == 3:
        score += 15
        bonuses.append("Uses 3 character classes")
    elif char_classes == 2:
        score += 5
        feedback.append("Add symbols or mix upper/lowercase to strengthen your password.")
    else:
        score -= 10
        penalties.append("Only one character class used")
        feedback.append("Mix uppercase, lowercase, numbers, and symbols.")

    # ── Entropy scoring ───────────────────────────────────────────────────────
    if entropy >= 80:
        score += 20
        bonuses.append(f"High entropy ({entropy:.1f} bits)")
    elif entropy >= 60:
        score += 15
        bonuses.append(f"Good entropy ({entropy:.1f} bits)")
    elif entropy >= 40:
        score += 8
    else:
        score -= 5
        penalties.append(f"Low entropy ({entropy:.1f} bits)")
        feedback.append("Use a longer, more varied password to increase unpredictability.")

    # ── Penalty: common password ──────────────────────────────────────────────
    if _is_common_password(password):
        score -= 40
        penalties.append("This is a commonly used password")
        feedback.append("Avoid common passwords like 'password123' or 'qwerty'.")

    # ── Penalty: keyboard walk ────────────────────────────────────────────────
    if _has_keyboard_walk(password):
        score -= 15
        penalties.append("Contains keyboard walk pattern (e.g. qwerty, asdfgh)")
        feedback.append("Avoid keyboard patterns like 'qwerty' or 'asdfgh'.")

    # ── Penalty: repeated characters ──────────────────────────────────────────
    if _has_repeated_chars(password):
        score -= 10
        penalties.append("Contains repeated characters (e.g. 'aaa', '111')")
        feedback.append("Avoid repeating the same character multiple times.")

    # ── Penalty: sequential characters ───────────────────────────────────────
    if _has_sequential_chars(password):
        score -= 10
        penalties.append("Contains sequential characters (e.g. 'abc', '123')")
        feedback.append("Avoid sequences like 'abc' or '123'.")

    # ── Penalty: username in password ─────────────────────────────────────────
    if _has_username_in_password(password, username):
        score -= 15
        penalties.append("Password contains your username")
        feedback.append("Do not include your username in your password.")

    # ── Clamp score to 0-100 ──────────────────────────────────────────────────
    score = max(0, min(100, score))

    if not feedback and score < 60:
        feedback.append("Consider using a passphrase: 4+ random words joined together.")

    return StrengthResult(
        score=score,
        label=_label_from_score(score),
        entropy=entropy,
        feedback=feedback,
        penalties=penalties,
        bonuses=bonuses,
    )