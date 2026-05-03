"""
Response filtering layer.

Even if a query passes RBAC, the model's response may leak tokens the user
should not see (PII, credentials, etc.). We redact those patterns unconditionally,
and additionally redact role-scoped terms when the user's role would not permit
them in a direct query.
"""
import re
from app.models import RoleEnum
from app.rbac.policy import RBACEngine
from app.chatbot.classifier import classify_query


# Universal redactions — applied regardless of role.
_UNIVERSAL_REDACTIONS = [
    # Emails
    (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "[REDACTED_EMAIL]"),
    # API keys / bearer tokens (generic high-entropy prefixes)
    (re.compile(r"\bsk-[A-Za-z0-9]{20,}\b"), "[REDACTED_API_KEY]"),
    (re.compile(r"\bBearer\s+[A-Za-z0-9._\-]{20,}\b", re.IGNORECASE), "[REDACTED_TOKEN]"),
    # Credit-card-shaped digits
    (re.compile(r"\b(?:\d[ -]*?){13,16}\b"), "[REDACTED_CC]"),
    # US SSN
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[REDACTED_SSN]"),
    # Private-key PEM block
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
     "[REDACTED_PRIVATE_KEY]"),
]


def filter_response(response_text: str, user_role: RoleEnum) -> str:
    """
    Scrub a model response before it leaves the server.
    - Always apply universal redactions.
    - If any sentence in the response would be classified above the user's max,
      replace that sentence with a redaction notice.
    """
    text = response_text

    # Universal redactions
    for pattern, replacement in _UNIVERSAL_REDACTIONS:
        text = pattern.sub(replacement, text)

    # Sentence-level role filtering
    # Split on . ! ? while keeping the delimiter with the sentence.
    sentences = re.split(r"(?<=[.!?])\s+", text)
    filtered = []
    for s in sentences:
        if not s.strip():
            continue
        sent_class = classify_query(s)
        if RBACEngine.is_permitted(user_role, sent_class):
            filtered.append(s)
        else:
            filtered.append("[REDACTED — above your role's access level]")
    return " ".join(filtered).strip()
