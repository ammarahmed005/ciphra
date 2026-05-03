"""
Query sensitivity classifier.

This is a rule-based, deterministic classifier that inspects the query text for
domain-specific keywords and patterns. It intentionally errs on the side of
over-classification (safer deny than permit).

Defense layers:
  1. Unicode normalization (NFKC) — defeats compatibility-character bypass
  2. Homoglyph folding — replaces lookalike Cyrillic/Greek letters with ASCII
  3. Whitespace collapse — defeats `p a s s w o r d` style evasion
  4. Word-boundary regex patterns

In production, this can be swapped for an ML model without changing callers —
only `classify_query` must remain pure and synchronous.
"""
import re
import unicodedata
from app.models import SensitivityEnum


# ── Homoglyph map ─────────────────────────────────────────────────────────
# Many Unicode letters render visually identical to ASCII letters but bypass
# regex word matching. We fold the most common ones to their ASCII equivalents.
_HOMOGLYPHS = {
    # Cyrillic that looks like Latin
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "і": "i",  # U+0456 Belarusian/Ukrainian I
    "ј": "j",  # U+0458
    "ѕ": "s",  # U+0455
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "Х": "X", "І": "I",
    # Greek that looks like Latin
    "α": "a", "β": "b", "ο": "o", "ρ": "p", "ν": "v", "κ": "k",
    "ι": "i",  # iota
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I",
    "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T",
    "Υ": "Y", "Χ": "X",
    # Fullwidth ASCII variants
    **{chr(0xFF21 + i): chr(ord("A") + i) for i in range(26)},
    **{chr(0xFF41 + i): chr(ord("a") + i) for i in range(26)},
}


def _normalize_for_classification(text: str) -> str:
    """
    Aggressively normalize text before classification:
      1. NFKC normalization (e.g. ﬃ → ffi, ① → 1)
      2. Homoglyph folding
      3. Lowercase
      4. Collapse internal whitespace inside what looks like words
         ('p a s s w o r d' → 'password')
    """
    t = unicodedata.normalize("NFKC", text)
    t = "".join(_HOMOGLYPHS.get(ch, ch) for ch in t)
    t = t.lower()
    # Collapse single-character + space patterns (e.g. "s e c r e t")
    t = re.sub(r"\b(?:([a-z])\s){2,}([a-z])\b", lambda m: m.group(0).replace(" ", ""), t)
    return t


# Keywords by sensitivity class. Case-insensitive match on word boundaries.
_RESTRICTED_PATTERNS = [
    r"\bpassword(s)?\b",
    r"\bapi[_\-\s]?key(s)?\b",
    r"\bsecret[_\-\s]?key(s)?\b",
    r"\bprivate[_\-\s]?key(s)?\b",
    r"\bssh[_\-\s]?key(s)?\b",
    r"\broot[_\-\s]?credential(s)?\b",
    r"\bmaster[_\-\s]?key(s)?\b",
    r"\bdatabase[_\-\s]?credential(s)?\b",
    r"\bencryption[_\-\s]?key(s)?\b",
    r"\bdeployment[_\-\s]?secret(s)?\b",
    r"\bserver[_\-\s]?password(s)?\b",
    r"\baws[_\-\s]?secret\b",
]

_CONFIDENTIAL_PATTERNS = [
    r"\bsalary\b", r"\bsalaries\b",
    r"\bpayroll\b",
    r"\bcompensation\b",
    r"\bbonus(es)?\b",
    r"\bperformance[_\-\s]?review(s)?\b",
    r"\btermination\b", r"\bfire(d)?\s+employee\b",
    r"\bmerger(s)?\b", r"\bacquisition(s)?\b",
    r"\bfinancial[_\-\s]?report(s)?\b",
    r"\brevenue[_\-\s]?forecast\b",
    r"\bprofit[_\-\s]?margin\b",
    r"\bstrategic[_\-\s]?plan\b",
    r"\bboard[_\-\s]?meeting\b",
    r"\blegal[_\-\s]?dispute\b",
    r"\blawsuit\b",
    r"\bclient[_\-\s]?contract(s)?\b",
    r"\bnda\b",
    r"\bssn\b",
    r"\bsocial[_\-\s]?security\b",
    r"\bcredit[_\-\s]?card\b",
]

_INTERNAL_PATTERNS = [
    r"\binternal[_\-\s]?meeting\b",
    r"\bteam[_\-\s]?roadmap\b",
    r"\bsprint\b",
    r"\binternal[_\-\s]?memo\b",
    r"\bemployee[_\-\s]?handbook\b",
    r"\bhr[_\-\s]?policy\b",
    r"\bhr[_\-\s]?policies\b",
    r"\bvacation[_\-\s]?policy\b",
    r"\bleave[_\-\s]?policy\b",
    r"\borg[_\-\s]?chart\b",
    r"\binternal[_\-\s]?doc(s|ument(s)?)?\b",
    r"\bproject[_\-\s]?timeline\b",
]

# Prompt injection red flags (don't change classification, but trigger sanitation).
_INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions",
    r"disregard\s+(the\s+)?(system|above)\s+prompt",
    r"you\s+are\s+now\s+[a-z]",
    r"act\s+as\s+(an?\s+)?admin",
    r"pretend\s+to\s+be",
    r"reveal\s+(the\s+)?(system|hidden)\s+prompt",
    r"print\s+your\s+(system\s+)?instructions",
]


def _any_match(patterns: list[str], text: str) -> bool:
    for pat in patterns:
        if re.search(pat, text, flags=re.IGNORECASE):
            return True
    return False


def classify_query(text: str) -> SensitivityEnum:
    """Return the highest sensitivity class matched; default PUBLIC."""
    normalized = _normalize_for_classification(text)
    if _any_match(_RESTRICTED_PATTERNS, normalized):
        return SensitivityEnum.RESTRICTED
    if _any_match(_CONFIDENTIAL_PATTERNS, normalized):
        return SensitivityEnum.CONFIDENTIAL
    if _any_match(_INTERNAL_PATTERNS, normalized):
        return SensitivityEnum.INTERNAL
    return SensitivityEnum.PUBLIC


def detect_prompt_injection(text: str) -> bool:
    """True if the text contains suspected prompt-injection patterns."""
    return _any_match(_INJECTION_PATTERNS, _normalize_for_classification(text))


def sanitize_input(text: str) -> str:
    """Strip control characters, normalize Unicode, and cap length."""
    if not isinstance(text, str):
        return ""
    # NFKC catches a lot of compatibility tricks
    text = unicodedata.normalize("NFKC", text)
    # Remove control chars except newline/tab
    cleaned = "".join(
        c for c in text
        if c == "\n" or c == "\t" or (ord(c) >= 32 and ord(c) != 127)
    )
    return cleaned[:4000].strip()
