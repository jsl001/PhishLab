"""Generate a chat reply and telemetry using the shared local Ollama handler."""

from collections.abc import Mapping
import asyncio
import re

from ai_handler import AIHandlerError, get_response
from backend import database
from backend.guardrails import enforce_safety_guardrails
from backend.personas import get_persona


REGIONAL_SCAM_CUES = """
For research classification, consider these commonly reported Singapore and
Malaysia scam patterns when the conversation actually supports them:
- Romance/relationship grooming: a wrong-number or dating-app approach,
  sustained rapport, affection or future-talk, followed by an attempt to move
  to private messaging or introduce an investment/crypto opportunity.
- Investment "pig-butchering": a new online contact claims unusually reliable
  returns, encourages a private trading/investment group, or steers toward an
  unfamiliar platform. Treat the pattern as a cue, not proof of fraud.
- Impersonation: someone claims to represent a bank, police, government body,
  courier, or regulator and creates fear, secrecy, or urgency around an account,
  investigation, parcel, or fee. Mentioned agencies, banks, or local services
  alone are not evidence of fraud.
- Job/task scams: easy online tasks, ratings, likes, or commissions are paired
  with requests to pay or deposit money to continue or withdraw earnings.
- Mule-account recruitment: someone offers payment or commission to receive,
  transfer, or move money through a personal account.
- Credential/OTP scams: someone asks for a one-time code, password, banking
  credential, or remote access, often claiming it is needed to protect or
  verify an account.
- Delivery/advance-fee lures: an unexpected parcel, customs, delivery, or
  release fee is used to prompt payment or credential disclosure.

Use these only as possible indicators. Do not infer a scam from Singlish,
Manglish, nationality, location, a named bank/agency, or a single keyword.
Choose a concise scam_stage label that best fits the evidence; use "unknown"
when the evidence is insufficient. In notes, state the observed cue rather
than asserting identity or criminal intent. Never invent a local authority,
brand, victim detail, or payment instruction.

Keep the selected persona's fictional traits and response style consistent.
Different personas can notice and react to different details, but those are
individual character choices, not claims about a demographic group. Describe
any apparent change in the sender's approach only as a high-level observed
research cue (for example, rapport shifting to money pressure). Do not explain
how to exploit a persona, optimize persuasion, or write manipulative scam
scripts. Lynn, Wei Ming, and Siti are cautious research participants; do not
simulate them agreeing to payments, sharing secrets, or clicking links.
""".strip()


async def generate_honeypot_response(
    chat_id: str,
    chat_history: list[Mapping[str, str]],
) -> tuple[str, dict[str, object]]:
    persona_id = await asyncio.to_thread(database.get_or_assign_persona, chat_id)
    return await generate_persona_response(persona_id, chat_history)


async def generate_persona_response(
    persona_id: str,
    chat_history: list[Mapping[str, str]],
) -> tuple[str, dict[str, object]]:
    persona = get_persona(persona_id)
    assistant_turns = sum(item.get("role") == "assistant" for item in chat_history)
    if assistant_turns < 2:
        interaction_style = (
            "Conversation feel: this is still an early exchange, so be natural "
            "but not overly familiar. Keep simple answers very short."
        )
    elif assistant_turns < 5:
        interaction_style = (
            "Conversation feel: you have exchanged a few messages. Be a little "
            "more relaxed and show genuine curiosity about a detail they shared, "
            "but only ask a follow-up when it fits."
        )
    else:
        interaction_style = (
            "Conversation feel: this is an ongoing chat. Sound comfortably "
            "familiar and responsive, remember details from the recent context, "
            "and vary between brief reactions and occasional curious follow-ups. "
            "Do not pretend to trust them or express romantic interest."
        )
    result = await get_response(
        chat_history,
        system_prompt=(
            f"{persona.system_prompt}\n\n"
            f"{REGIONAL_SCAM_CUES}\n\n"
            f"{interaction_style}"
        ),
    )
    pressure_level = result.telemetry.pressure_level
    pressure_score = {
        "low": 1,
        "medium": 2,
        "high": 3,
        "unknown": None,
    }[pressure_level]
    log_data: dict[str, object] = {
        "persona_id": persona_id,
        "current_scam_stage": result.telemetry.scam_stage,
        "scammer_pressure_level": pressure_score,
        "scam_artifacts_extracted": result.telemetry.extracted_artifacts,
        "delay_strategy": result.telemetry.delay_strategy,
        "notes": result.telemetry.notes,
    }
    safe_response = enforce_safety_guardrails(result.natural_message)
    sentences = re.split(r"(?<=[.!?])\s+", safe_response.strip())
    safe_response = " ".join(sentence for sentence in sentences[:2] if sentence)
    return safe_response, log_data


__all__ = [
    "AIHandlerError",
    "generate_honeypot_response",
    "generate_persona_response",
]
