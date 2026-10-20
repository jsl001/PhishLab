"""Async client for sending approved WhatsApp text messages through Meta."""

import logging
import os
import re

import httpx


logger = logging.getLogger(__name__)


class WhatsAppClientError(RuntimeError):
    """Raised when WhatsApp credentials or message delivery are unavailable."""


class SensitiveOutboundDataError(WhatsAppClientError):
    """Raised when outbound text contains sensitive personal or financial data."""


_NRIC_FIN_PATTERN = re.compile(r"(?<![A-Z0-9])[STFGM]\d{7}[A-Z](?![A-Z0-9])", re.IGNORECASE)
_CARD_NUMBER_PATTERN = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")
_IBAN_PATTERN = re.compile(
    r"(?<![A-Z0-9])[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}(?![A-Z0-9])",
    re.IGNORECASE,
)
_LABELED_ACCOUNT_PATTERN = re.compile(
    r"\b(?:bank\s+)?account\s*(?:number|no\.?|#)\s*[:#-]?\s*"
    r"((?:\d[ -]?){5,19}\d)\b",
    re.IGNORECASE,
)


def _passes_luhn(number: str) -> bool:
    digits = [int(character) for character in number if character.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False

    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def _passes_iban_checksum(iban: str) -> bool:
    normalized = re.sub(r"\s+", "", iban).upper()
    rearranged = normalized[4:] + normalized[:4]
    numeric = "".join(
        str(ord(character) - ord("A") + 10) if character.isalpha() else character
        for character in rearranged
    )
    remainder = 0
    for character in numeric:
        remainder = (remainder * 10 + int(character)) % 97
    return remainder == 1


def validate_outbound_payload(message_text: str) -> None:
    """Reject outbound text containing likely NRIC/FIN, card, or account data."""
    if not isinstance(message_text, str):
        raise TypeError("message_text must be a string")

    sensitive_category: str | None = None
    if _NRIC_FIN_PATTERN.search(message_text):
        sensitive_category = "NRIC/FIN identifier"
    elif any(
        _passes_luhn(match.group())
        for match in _CARD_NUMBER_PATTERN.finditer(message_text)
    ):
        sensitive_category = "payment card number"
    elif any(
        _passes_iban_checksum(match.group())
        for match in _IBAN_PATTERN.finditer(message_text)
    ):
        sensitive_category = "IBAN"
    elif _LABELED_ACCOUNT_PATTERN.search(message_text):
        sensitive_category = "labeled financial account number"

    if sensitive_category is not None:
        logger.error(
            "Blocked WhatsApp outbound payload containing a %s",
            sensitive_category,
        )
        raise SensitiveOutboundDataError(
            f"Outbound message blocked because it contains a {sensitive_category}"
        )


async def send_whatsapp_message(recipient_phone: str, message_text: str) -> None:
    validate_outbound_payload(message_text)
    token = os.getenv("WHATSAPP_TOKEN")
    phone_number_id = os.getenv("WHATSAPP_PHONE_NUMBER_ID")
    if not token or not phone_number_id:
        raise WhatsAppClientError(
            "WHATSAPP_TOKEN and WHATSAPP_PHONE_NUMBER_ID must be configured"
        )
    if not recipient_phone.strip():
        raise ValueError("recipient_phone must not be empty")
    if not message_text.strip():
        raise ValueError("message_text must not be empty")

    url = (
        "https://graph.facebook.net/v18.0/"
        f"{phone_number_id}/messages"
    )
    payload = {
        "messaging_product": "whatsapp",
        "recipient_type": "individual",
        "to": recipient_phone,
        "type": "text",
        "text": {"body": message_text},
    }

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(
                url,
                json=payload,
                headers={"Authorization": f"Bearer {token}"},
            )
            response.raise_for_status()
    except httpx.HTTPStatusError as exc:
        raise WhatsAppClientError(
            f"WhatsApp message delivery failed with HTTP {exc.response.status_code}"
        ) from exc
    except httpx.RequestError as exc:
        raise WhatsAppClientError("Could not reach the WhatsApp Graph API") from exc
