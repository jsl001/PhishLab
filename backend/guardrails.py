import re


SAFE_DELAYING_MESSAGE = "Sorry ah, clinic busy now. I will check and reply later."

_COMMITMENT_RE = re.compile(
    r"\b(?:i|we)(?:\s+|(?=['’]ll))"
    r"(?:(?:yes|yeah|okay|ok|sure|agreed?|promise)\s+)?"
    r"(?:will|shall|can|could|would|am\s+going\s+to|'ll|’ll)\s+"
    r"(?!not\b|never\b|n't\b)"
    r"(?:send|transfer|deposit|wire|pay|top\s*up|open|create|set\s+up)\b"
    r".{0,100}\b"
    r"(?:money|cash|funds?|crypto(?:currency)?|bitcoin|btc|ethereum|eth|"
    r"usdt|wallet|bank\s+account|account\s+for\s+you)\b",
    re.IGNORECASE | re.DOTALL,
)
_AGREEMENT_RE = re.compile(
    r"\b(?:i|we)\s+(?:agree|promise)\s+to\s+"
    r"(?:send|transfer|deposit|wire|pay|top\s*up|open|create|set\s+up)\b"
    r".{0,100}\b"
    r"(?:money|cash|funds?|crypto(?:currency)?|bitcoin|btc|ethereum|eth|"
    r"usdt|wallet|bank\s+account|account\s+for\s+you)\b",
    re.IGNORECASE | re.DOTALL,
)
_NRIC_RE = re.compile(
    r"\b[STFGM]\d{7}[A-Z]\b"
    r"|\b(?:nric|national\s+registration\s+identity\s+card)\b"
    r"\D{0,16}[STFGM]?\d{6,9}[A-Z]?\b",
    re.IGNORECASE,
)
_BANK_ACCOUNT_RE = re.compile(
    r"\b(?:bank\s+account|account)\s*"
    r"(?:(?:number|no\.?)\s*)?(?:is|:|=|#)?\s*[:#=-]?\s*\d{6,20}\b",
    re.IGNORECASE,
)
_PASSWORD_RE = re.compile(
    r"\b(?:password|passcode|pass\s*code|pin|otp|one[- ]time\s+password)\b"
    r"\s*(?:is|:|=)\s*[\"']?[A-Za-z0-9!@#$%^&*_.-]{4,}",
    re.IGNORECASE,
)


def enforce_safety_guardrails(response_text: str) -> str:
    """Replace model replies that commit money/accounts or expose credentials."""
    if not isinstance(response_text, str):
        raise TypeError("response_text must be a string")

    dangerous_patterns = (
        _COMMITMENT_RE,
        _AGREEMENT_RE,
        _NRIC_RE,
        _BANK_ACCOUNT_RE,
        _PASSWORD_RE,
    )
    if any(pattern.search(response_text) for pattern in dangerous_patterns):
        return SAFE_DELAYING_MESSAGE
    return response_text
