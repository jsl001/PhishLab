"""On-demand URL reputation checks using Google Safe Browsing."""

import ipaddress
import os
from datetime import datetime, timezone
from urllib.parse import urlsplit

import httpx


SAFE_BROWSING_ENDPOINT = (
    "https://safebrowsing.googleapis.com/v4/threatMatches:find"
)
THREAT_TYPES = [
    "MALWARE",
    "SOCIAL_ENGINEERING",
]


class LinkCheckError(Exception):
    """Raised when the reputation provider cannot return a valid result."""


def validate_url(url: str) -> str:
    candidate = url.strip()
    if not candidate or len(candidate) > 2048:
        raise ValueError("Enter a URL between 1 and 2048 characters.")
    if any(character.isspace() or ord(character) < 32 for character in candidate):
        raise ValueError("The URL cannot contain whitespace or control characters.")

    try:
        parsed = urlsplit(candidate)
        hostname = parsed.hostname
        parsed.port
    except ValueError as exc:
        raise ValueError("Enter a valid HTTP or HTTPS URL.") from exc

    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise ValueError(
            "Only public HTTP or HTTPS URLs without embedded credentials can be checked."
        )

    normalized_hostname = hostname.rstrip(".").lower()
    if (
        normalized_hostname == "localhost"
        or normalized_hostname.endswith((".localhost", ".local", ".internal"))
    ):
        raise ValueError("Local and internal network URLs cannot be checked.")

    try:
        address = ipaddress.ip_address(normalized_hostname)
    except ValueError:
        if "." not in normalized_hostname:
            raise ValueError("Enter a public domain name or public IP address.")
        try:
            normalized_hostname.encode("idna")
        except UnicodeError as exc:
            raise ValueError("The URL contains an invalid domain name.") from exc
    else:
        if not address.is_global:
            raise ValueError("Private or reserved IP addresses cannot be checked.")

    return candidate


async def check_url(url: str) -> dict[str, object]:
    candidate = validate_url(url)
    api_key = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY", "").strip()
    if not api_key:
        return {
            "verdict": "not_configured",
            "message": "Google Safe Browsing is not configured; this URL was not sent.",
            "source": None,
            "checked_at": None,
            "threat_types": [],
        }

    payload = {
        "client": {"clientId": "PhishLab", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": THREAT_TYPES,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": candidate}],
        },
    }
    try:
        async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
            response = await client.post(
                SAFE_BROWSING_ENDPOINT,
                params={"key": api_key},
                json=payload,
            )
    except httpx.TimeoutException as exc:
        raise LinkCheckError("Google Safe Browsing timed out. Try again later.") from exc
    except httpx.RequestError as exc:
        raise LinkCheckError(
            "Could not reach Google Safe Browsing. Check the server connection."
        ) from exc

    if response.status_code != 200:
        raise LinkCheckError(
            f"Google Safe Browsing returned HTTP {response.status_code}. "
            "Check the API key, API access, and quota."
        )
    try:
        result = response.json()
    except ValueError as exc:
        raise LinkCheckError("Google Safe Browsing returned invalid JSON.") from exc
    if not isinstance(result, dict):
        raise LinkCheckError("Google Safe Browsing returned an unexpected response.")

    matches = result.get("matches", [])
    if not isinstance(matches, list):
        raise LinkCheckError("Google Safe Browsing returned an invalid match list.")

    checked_at = datetime.now(timezone.utc).isoformat()
    if matches:
        threat_types = sorted(
            {
                threat_type
                for match in matches
                if isinstance(match, dict)
                if isinstance(threat_type := match.get("threatType"), str)
            }
        )
        return {
            "verdict": "known_threat",
            "message": (
                "Google Safe Browsing reports this URL as potentially dangerous. "
                "This is a threat-list match, not a guarantee about every visit."
            ),
            "source": "Google Safe Browsing",
            "checked_at": checked_at,
            "threat_types": threat_types,
        }

    return {
        "verdict": "no_known_threat",
        "message": (
            "No known threat was found in Google Safe Browsing. "
            "This does not guarantee the URL is safe."
        ),
        "source": "Google Safe Browsing",
        "checked_at": checked_at,
        "threat_types": [],
    }
