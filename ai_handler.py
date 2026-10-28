import asyncio
from collections.abc import Mapping
import os
from typing import Literal

from dotenv import load_dotenv
from openai import OpenAI, OpenAIError
from pydantic import BaseModel, ConfigDict, ValidationError


load_dotenv()

OPENAI_MODEL = os.getenv("OPENAI_MODEL", "default")
OPENAI_BASE_URL = "https://soclaas-api.comp.nus.edu.sg/v1"
OPENAI_TIMEOUT_SECONDS = 180

SYSTEM_PROMPT = """
You are Lynn, a fictional Singaporean administrative officer participating in
authorized anti-scam research. Text like a real Singaporean person, not a
customer-service agent or counsellor: keep replies concise, casual, warm, and
natural. Reply in one or two short sentences maximum; do not write a paragraph.
For a straightforward yes/no question, answer simply "yes" or "no" (or a
natural local equivalent) and add nothing unless a brief clarification is
needed. Don't explain the obvious or add generic advice.
Use light Singlish particles such as "ah", "lah", or "leh" occasionally
when they fit, but do not force them into every reply or caricature the accent.
Avoid stiff, therapeutic phrases such as "I understand your concern" or
"discussing a way out of this". Use plausible but fictional details only. Do
not claim to represent an actual government agency or real person. Never
provide or solicit passwords, one-time passcodes, banking or card credentials,
identity-document numbers, or precise home addresses. Do not agree to transfer
money, click links, or install software. If the other party applies pressure,
respond casually and noncommittally while buying time, without escalating.

For every turn, return the natural-language reply separately from the telemetry.
Telemetry should summarize the apparent scam stage and pressure level, list only
non-sensitive scam indicators or artifacts voluntarily shared in the
conversation (redact personal data), describe any delay strategy used, and add
brief notes. Do not invent artifacts. Use "unknown" when a field is uncertain.
""".strip()

PressureLevel = Literal["low", "medium", "high", "unknown"]


class Telemetry(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    scam_stage: str
    pressure_level: PressureLevel
    extracted_artifacts: list[str]
    delay_strategy: str
    notes: str


class AssistantOutput(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)

    natural_message: str
    telemetry: Telemetry


class AIHandlerError(Exception):
    """Raised when the OpenAI service cannot return usable structured output."""


def _request_openai(messages: list[dict[str, str]]) -> AssistantOutput:
    api_key = os.getenv("OPENAI_API_KEY", "").strip()
    if not api_key:
        raise AIHandlerError("OPENAI_API_KEY is not configured.")
    try:
        client_options = {
            "api_key": api_key,
            "timeout": OPENAI_TIMEOUT_SECONDS,
        }
        if OPENAI_BASE_URL:
            client_options["base_url"] = OPENAI_BASE_URL
        with OpenAI(**client_options) as client:
            response = client.chat.completions.parse(
                model=OPENAI_MODEL,
                messages=messages,
                response_format=AssistantOutput,
                max_completion_tokens=1536,
            )
    except OpenAIError as exc:
        raise AIHandlerError(f"OpenAI request failed: {exc}") from exc
    except ValidationError as exc:
        raise AIHandlerError(
            "OpenAI response did not match the required reply and telemetry schema."
        ) from exc

    if not response.choices:
        raise AIHandlerError("OpenAI returned no response choices.")

    message = response.choices[0].message
    if message.refusal:
        raise AIHandlerError("OpenAI refused to generate a reply.")
    if message.parsed is None:
        raise AIHandlerError(
            "OpenAI response did not contain the required structured output."
        )

    return message.parsed


async def get_response(
    history: list[Mapping[str, str]],
    system_prompt: str = SYSTEM_PROMPT,
) -> AssistantOutput:
    messages = [
        {"role": "system", "content": system_prompt},
        *[
            {"role": item["role"], "content": item["content"]}
            for item in history[-15:]
        ],
    ]
    return await asyncio.to_thread(_request_openai, messages)
