"""Deterministic extraction of reviewable indicators from inbound messages."""

import re
from urllib.parse import urlsplit

from backend.classifier import ScamClassifierEngine

_URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_PHONE_RE = re.compile(r"(?<!\w)(?:\+?65[\s-]?)?[689]\d{3}[\s-]?\d{4}(?!\w)")
_UEN_RE = re.compile(r"\b(?:UEN\s*[:#-]?\s*)?[0-9]{8,10}[A-Z]?\b", re.IGNORECASE)
_PAYNOW_RE = re.compile(r"\b(?:PayNow|PayLah)\b[^\n]{0,80}", re.IGNORECASE)


def _clean(value: str) -> str:
    return value.rstrip(".,!?;:)")


def extract_indicators(message_text: str) -> list[dict[str, str]]:
    """Extract candidate indicators; all results require human review."""
    indicators: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: str) -> None:
        value = _clean(value.strip())
        key = (kind, value.lower())
        if value and key not in seen:
            seen.add(key)
            indicators.append({"artifact_type": kind, "artifact_value": value})

    for match in _URL_RE.finditer(message_text):
        url = _clean(match.group())
        add("url", url)
        hostname = urlsplit(url).hostname
        if hostname:
            add("domain", hostname.lower())

    for match in _PHONE_RE.finditer(message_text):
        digits = re.sub(r"\D", "", match.group())
        normalized = f"+65{digits[-8:]}" if len(digits) == 8 else f"+{digits}"
        add("phone_number", normalized)

    for match in _UEN_RE.finditer(message_text):
        if "UEN" in match.group().upper():
            add("uen_candidate", match.group())

    for match in _PAYNOW_RE.finditer(message_text):
        add("payment_reference", match.group())

    return indicators


def classify_inbound_message(message_text: str) -> dict[str, object]:
    result = ScamClassifierEngine.analyze([
        {"role": "user", "content": message_text},
    ])
    return {
        "scam_score": result["scam_score"],
        "is_scam": result["is_scam"],
        "detected_flags": result["detected_flags"],
        "indicators": extract_indicators(message_text),
    }
