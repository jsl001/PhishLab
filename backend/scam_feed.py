"""Load Singapore scam terminology from official advisory pages and RSS feeds."""

import logging
import os
import re
from datetime import UTC, datetime
from html.parser import HTMLParser
from urllib.parse import urlparse
from xml.etree import ElementTree

import httpx


logger = logging.getLogger(__name__)

SCAMSHIELD_HOME_URL = "https://www.scamshield.gov.sg/"
MAX_RESPONSE_BYTES = 1_000_000
MAX_DYNAMIC_KEYWORDS = 50
FEED_REFRESH_INTERVAL_SECONDS = 6 * 60 * 60

DYNAMIC_KEYWORDS: list[str] = []
SCAMSHIELD_SYNCED = False
LAST_SCAMSHIELD_SYNC_AT: str | None = None

_SCAM_CONTEXT = re.compile(
    r"\b(?:scam|scams|fraud|phishing|impersonation)\s+"
    r"(?:involving|using|via|through|targeting|on|with)\s+"
    r"([A-Za-z][A-Za-z0-9'’ -]{1,40})",
    re.IGNORECASE,
)
_REVERSE_SCAM_CONTEXT = re.compile(
    r"\b((?:[A-Za-z0-9]+(?:['’-][A-Za-z0-9]+)?\s+){0,2}"
    r"[A-Za-z0-9]+(?:['’-][A-Za-z0-9]+)?)\s+"
    r"(?:scam|scams|fraud|phishing|impersonation)\b",
    re.IGNORECASE,
)
_NAMED_SCAM_SERVICE = re.compile(
    r"\b(?:fake|fraudulent|scam)\s+"
    r"[\"'“]?([A-Z][A-Za-z0-9]+(?:\s+[A-Z][A-Za-z0-9]+){0,2})"
)
_PHRASE_CONNECTORS = re.compile(
    r"\b(?:and|or|to|with|for|that|which|where|when|as|by|from|"
    r"are|is|was|were|be|being|been|reported|found|detected|seen|"
    r"announced|warned|warn|says|said)\b.*$",
    re.IGNORECASE,
)
_TRAILING_STOP_WORDS = {
    "and",
    "or",
    "to",
    "with",
    "for",
    "that",
    "which",
    "where",
    "when",
    "as",
    "by",
    "from",
    "of",
}
_GENERIC_KEYWORDS = {
    "a",
    "an",
    "beware",
    "common",
    "brief",
    "fake",
    "five",
    "local",
    "news",
    "online",
    "police",
    "efforts",
    "mid-year",
    "new",
    "latest",
    "of",
    "types",
    "users",
    "victims",
    "reported",
    "suspected",
    "related",
    "related to",
    "involving",
    "targeting",
}


class _PageTextExtractor(HTMLParser):
    """Collect visible page text while omitting script and style bodies."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._ignored_depth = 0

    def handle_starttag(
        self,
        tag: str,
        attrs: list[tuple[str, str | None]],
    ) -> None:
        _ = attrs
        if tag.lower() in {"script", "style", "noscript"}:
            self._ignored_depth += 1

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() in {"script", "style", "noscript"} and self._ignored_depth:
            self._ignored_depth -= 1

    def handle_data(self, data: str) -> None:
        if not self._ignored_depth:
            self.parts.append(data)


class ScamFeedError(RuntimeError):
    """Raised when no configured advisory source can be fetched."""


def _configured_rss_urls() -> list[str]:
    raw_urls = os.getenv("SCAM_ADVISORY_RSS_URLS", "")
    return [url.strip() for url in raw_urls.split(",") if url.strip()]


def _validate_source_url(url: str) -> None:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or not host:
        raise ValueError("Advisory URLs must use HTTPS and include a hostname")
    if not (
        host == "scamshield.gov.sg"
        or host.endswith(".scamshield.gov.sg")
        or host == "police.gov.sg"
        or host.endswith(".police.gov.sg")
    ):
        raise ValueError("Advisory URLs must use an official ScamShield or SPF host")


def _fetch_source(url: str) -> bytes:
    _validate_source_url(url)
    with httpx.Client(timeout=10.0, follow_redirects=False) as client:
        with client.stream(
            "GET",
            url,
            headers={"User-Agent": "PhishLensResearchPrototype/1.0"},
        ) as response:
            response.raise_for_status()
            chunks: list[bytes] = []
            response_size = 0
            for chunk in response.iter_bytes():
                response_size += len(chunk)
                if response_size > MAX_RESPONSE_BYTES:
                    raise ValueError("Advisory response exceeds the size limit")
                chunks.append(chunk)
            return b"".join(chunks)


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].lower()


def _extract_rss_text(payload: bytes) -> str:
    root = ElementTree.fromstring(payload)
    parts: list[str] = []
    for element in root.iter():
        if _local_name(element.tag) in {"title", "description", "summary", "encoded"}:
            if element.text:
                parts.append(element.text)
    return " ".join(parts)


def _extract_page_text(payload: bytes) -> str:
    parser = _PageTextExtractor()
    parser.feed(payload.decode("utf-8", errors="replace"))
    return " ".join(parser.parts)


def _normalize_candidate(candidate: str) -> str | None:
    words = re.findall(r"[A-Za-z0-9]+(?:['’-][A-Za-z0-9]+)?", candidate)
    while words and words[0].lower() in _GENERIC_KEYWORDS:
        words.pop(0)
    while words and words[-1].lower() in _TRAILING_STOP_WORDS:
        words.pop()
    words = words[:3]
    keyword = " ".join(words).strip()
    has_named_term = any(
        word.isupper() and len(word) > 1
        or any(character.isupper() for character in word[1:])
        for word in words
    ) or (bool(words) and words[0].casefold() == "scam" and len(words) > 1)
    if (
        not keyword
        or len(keyword) < 3
        or keyword.casefold() in _GENERIC_KEYWORDS
        or keyword.isdecimal()
        or not has_named_term
    ):
        return None
    return keyword


def _extract_keywords(text: str) -> set[str]:
    candidates: set[str] = set()
    for pattern in (
        _SCAM_CONTEXT,
        _REVERSE_SCAM_CONTEXT,
        _NAMED_SCAM_SERVICE,
    ):
        for match in pattern.finditer(text):
            candidate = re.split(
                r"[,.;:!?()\n]",
                match.group(1),
                maxsplit=1,
            )[0]
            candidate = _PHRASE_CONNECTORS.sub("", candidate).strip()
            normalized = _normalize_candidate(candidate)
            if normalized:
                candidates.add(normalized)
    return candidates


def _extract_homepage_keywords(text: str) -> set[str]:
    alert_start = re.search(r"\bLATEST\s+SCAM\s+ALERT\b", text, re.IGNORECASE)
    if alert_start is None:
        return set()

    alert_text = text[alert_start.start() : alert_start.start() + 700]
    learn_more = re.search(r"\bLearn more\b", alert_text, re.IGNORECASE)
    if learn_more is not None:
        alert_text = alert_text[: learn_more.start()]
    return _extract_keywords(alert_text)


def fetch_latest_sg_scam_keywords() -> list[str]:
    """Refresh dynamic terms from ScamShield and configured official RSS feeds."""
    global SCAMSHIELD_SYNCED, LAST_SCAMSHIELD_SYNC_AT

    sources = [SCAMSHIELD_HOME_URL, *_configured_rss_urls()]
    collected_terms: set[str] = set()
    successful_sources = 0
    scamshield_succeeded = False

    for url in sources:
        try:
            payload = _fetch_source(url)
            if url == SCAMSHIELD_HOME_URL:
                source_text = _extract_page_text(payload)
                source_keywords = _extract_homepage_keywords(source_text)
            else:
                source_text = _extract_rss_text(payload)
                source_keywords = _extract_keywords(source_text)
            collected_terms.update(source_keywords)
            successful_sources += 1
            if url == SCAMSHIELD_HOME_URL:
                scamshield_succeeded = True
        except (
            httpx.HTTPError,
            ElementTree.ParseError,
            UnicodeError,
            ValueError,
        ) as exc:
            logger.warning("Could not refresh scam advisories from %s: %s", url, exc)

    if successful_sources == 0:
        SCAMSHIELD_SYNCED = False
        raise ScamFeedError("No Singapore scam advisory source could be fetched")

    updated_keywords = sorted(
        collected_terms,
        key=lambda keyword: (keyword.casefold(), keyword),
    )[:MAX_DYNAMIC_KEYWORDS]
    DYNAMIC_KEYWORDS[:] = updated_keywords
    SCAMSHIELD_SYNCED = scamshield_succeeded
    if scamshield_succeeded:
        LAST_SCAMSHIELD_SYNC_AT = datetime.now(UTC).isoformat()
    logger.info(
        "Refreshed %d dynamic scam keywords from %d advisory source(s)",
        len(DYNAMIC_KEYWORDS),
        successful_sources,
    )
    return DYNAMIC_KEYWORDS.copy()


def get_feed_status() -> dict[str, str | bool | int | None]:
    """Return whether the ScamShield homepage was reached in the last refresh."""
    return {
        "scamshield_synced": SCAMSHIELD_SYNCED,
        "last_synced_at": LAST_SCAMSHIELD_SYNC_AT,
        "dynamic_keyword_count": len(DYNAMIC_KEYWORDS),
    }
