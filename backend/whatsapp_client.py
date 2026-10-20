"""Async client for sending approved WhatsApp text messages through Meta."""

import os

import httpx


class WhatsAppClientError(RuntimeError):
    """Raised when WhatsApp credentials or message delivery are unavailable."""


async def send_whatsapp_message(recipient_phone: str, message_text: str) -> None:
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
