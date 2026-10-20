"""Heuristic multi-turn scam-pattern classifier for conversation review."""

import re
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any, TypedDict

from backend.scam_feed import DYNAMIC_KEYWORDS


SCAM_REVIEW_THRESHOLD = 50
HIGH_RISK_ALERT_THRESHOLD = 75


class ScamClassifierResult(TypedDict):
    scam_score: int
    is_scam: bool
    detected_flags: list[str]


class HighRiskAlert(TypedDict):
    event: str
    priority: str
    chat_id: str
    scam_score: int
    detected_flags: list[str]
    created_at: str


def check_and_notify_high_risk(
    chat_id: str,
    scam_score: int,
    flags: list[str],
) -> HighRiskAlert | None:
    """Build an alert payload when a heuristic score meets the high-risk threshold."""
    if scam_score < HIGH_RISK_ALERT_THRESHOLD:
        return None
    return {
        "event": "high_risk_scam_detection",
        "priority": "high",
        "chat_id": chat_id,
        "scam_score": scam_score,
        "detected_flags": list(flags),
        "created_at": datetime.now(UTC).isoformat(),
    }


class ScamClassifierEngine:
    """Score observable scam-pattern cues across the most recent five turns."""

    FLAG_WEIGHTS = {
        "WRONG_NUMBER_PIVOT": 30,
        "WEALTH_FLEX": 25,
        "PLATFORM_PIVOT": 35,
        "PRESSURE_TACTICS": 20,
        "CDC_VOUCHER_PHISHING": 25,
        "GOV_IMPERSONATION": 30,
        "LOCAL_PAYMENT_TRAPS": 25,
        "DYNAMIC_SG_ADVISORY": 15,
    }
    DECISION_THRESHOLD = SCAM_REVIEW_THRESHOLD
    HISTORY_WINDOW = 5

    _wrong_number_correction = re.compile(
        r"\b(?:wrong number|wrong person|you have the wrong|not (?:the person|mei))\b",
        re.IGNORECASE,
    )
    _rapport_pivot = re.compile(
        r"\b(?:fate|destiny|meant to (?:meet|connect)|"
        r"nice (?:talking|chatting|meeting)|enjoy (?:talking|chatting)|"
        r"you seem nice|let'?s be friends|how (?:is|was) your (?:day|week))\b",
        re.IGNORECASE,
    )
    _wealth_flex = re.compile(
        r"\b(?:crypto(?:currency)?|USDT|forex|"
        r"trading\s+(?:uncle|aunt)s?|"
        r"guaranteed\s+(?:returns?|profits?)|"
        r"(?:returns?|profits?)\s+(?:are\s+)?guaranteed|"
        r"high\s+returns?)\b",
        re.IGNORECASE,
    )
    _platform_switch = re.compile(
        r"\b(?:"
        r"(?:move|switch|come|continue|chat|message|talk|add)\s+"
        r"(?:over\s+)?(?:to|on|me\s+on)\s+"
        r"(?:telegram|whatsapp)|"
        r"(?:telegram|whatsapp)\s+(?:me|instead|is easier)|"
        r"(?:use|message me on|add me on)\s+(?:telegram|whatsapp)"
        r")\b",
        re.IGNORECASE,
    )
    _short_link_or_apk = re.compile(
        r"\b(?:short\s+link|apk|android\s+package|"
        r"install\s+(?:this|the)\s+app)\b|"
        r"\b(?:bit\.ly|tinyurl\.com|t\.me|cutt\.ly|"
        r"tiny\.cc|is\.gd)/\S+",
        re.IGNORECASE,
    )
    _urgency = re.compile(
        r"\b(?:urgent(?:ly)?|immediately|right now|"
        r"today only|before (?:it|the offer) expires|"
        r"last chance|limited time|deadline|expires tonight)\b",
        re.IGNORECASE,
    )
    _guilt = re.compile(
        r"\b(?:after all i(?:'| a)m doing|don't you trust me|"
        r"if you cared|you owe me|i thought you cared|"
        r"you are letting me down|disappointed in you)\b",
        re.IGNORECASE,
    )
    _financial_action = re.compile(
        r"\b(?:pay|transfer|deposit|top\s*up|invest|"
        r"withdraw|remit|wire|send money|buy crypto|"
        r"make a payment|share (?:your )?(?:bank|account) details)\b",
        re.IGNORECASE,
    )
    _cdc_voucher_phishing = re.compile(
        r"\b(?:CDC\s+vouchers?|RedeemSG|transport\s+vouchers?|GST\s+payouts?)\b",
        re.IGNORECASE,
    )
    _government_impersonation = re.compile(
        r"\bSingpass\b.{0,30}\bOTPs?\b|"
        r"\bOTPs?\b.{0,30}\bSingpass\b|"
        r"\bIRAS\b.{0,30}\btax\s+refunds?\b|"
        r"\btax\s+refunds?\b.{0,30}\bIRAS\b|"
        r"\b(?:DBS|OCBC)\b.{0,40}\b(?:fraud|security)\s+teams?\b|"
        r"\b(?:fraud|security)\s+teams?\b.{0,40}\b(?:DBS|OCBC)\b|"
        r"\bSPF\s+officers?\b|"
        r"\bofficers?\s+(?:from|with)\s+SPF\b",
        re.IGNORECASE,
    )
    _local_payment_traps = re.compile(
        r"\bPayNow\b|\bPayLah\b|"
        r"\b(?:bank|banking)\b.{0,40}\b(?:OTPs?|phishing\s+links?|links?)\b|"
        r"\b(?:OTPs?|phishing\s+links?)\b.{0,40}\b(?:bank|banking)\b",
        re.IGNORECASE,
    )

    @classmethod
    def analyze(
        cls,
        conversation_history: list[Mapping[str, Any]],
    ) -> ScamClassifierResult:
        """Return a capped heuristic score and matching behavioral flags."""
        recent_messages = conversation_history[-cls.HISTORY_WINDOW :]
        incoming_texts = [
            cls._message_text(message)
            for message in recent_messages
            if cls._is_incoming(message)
        ]
        incoming_texts = [text for text in incoming_texts if text]
        all_incoming_text = "\n".join(incoming_texts)
        flags: list[str] = []

        correction_seen = any(
            cls._is_persona_reply(message)
            and cls._wrong_number_correction.search(cls._message_text(message))
            for message in recent_messages
        )
        pivot_after_correction = False
        if correction_seen:
            correction_index = max(
                index
                for index, message in enumerate(recent_messages)
                if cls._is_persona_reply(message)
                and cls._wrong_number_correction.search(cls._message_text(message))
            )
            pivot_after_correction = any(
                index > correction_index
                and cls._is_incoming(message)
                and cls._rapport_pivot.search(cls._message_text(message))
                for index, message in enumerate(recent_messages)
            )
        if pivot_after_correction:
            flags.append("WRONG_NUMBER_PIVOT")

        if cls._wealth_flex.search(all_incoming_text):
            flags.append("WEALTH_FLEX")
        if (
            cls._platform_switch.search(all_incoming_text)
            or cls._short_link_or_apk.search(all_incoming_text)
        ):
            flags.append("PLATFORM_PIVOT")
        if (
            cls._urgency.search(all_incoming_text)
            or cls._guilt.search(all_incoming_text)
            or cls._financial_action.search(all_incoming_text)
        ):
            flags.append("PRESSURE_TACTICS")
        if cls._cdc_voucher_phishing.search(all_incoming_text):
            flags.append("CDC_VOUCHER_PHISHING")
        if cls._government_impersonation.search(all_incoming_text):
            flags.append("GOV_IMPERSONATION")
        if cls._local_payment_traps.search(all_incoming_text):
            flags.append("LOCAL_PAYMENT_TRAPS")
        if cls._matches_dynamic_keyword(all_incoming_text):
            flags.append("DYNAMIC_SG_ADVISORY")

        score = min(100, sum(cls.FLAG_WEIGHTS[flag] for flag in flags))
        return {
            "scam_score": score,
            "is_scam": score >= cls.DECISION_THRESHOLD,
            "detected_flags": flags,
        }

    @staticmethod
    def _message_text(message: Mapping[str, Any]) -> str:
        content = message.get("content", message.get("message_text", ""))
        return content if isinstance(content, str) else ""

    @staticmethod
    def _is_incoming(message: Mapping[str, Any]) -> bool:
        return message.get("role", message.get("sender")) in {
            "user",
            "scammer",
            "incoming",
        }

    @staticmethod
    def _is_persona_reply(message: Mapping[str, Any]) -> bool:
        return message.get("role", message.get("sender")) in {
            "assistant",
            "bot",
            "reply",
        }

    @staticmethod
    def _matches_dynamic_keyword(text: str) -> bool:
        return any(
            re.search(
                rf"(?<!\w){re.escape(keyword.strip())}(?!\w)",
                text,
                re.IGNORECASE,
            )
            is not None
            for keyword in DYNAMIC_KEYWORDS
            if keyword.strip()
        )
