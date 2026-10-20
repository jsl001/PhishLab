import asyncio
from collections.abc import Mapping
import json
import os
from pathlib import Path
from typing import Literal
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from dotenv import load_dotenv
from pydantic import BaseModel, ConfigDict, ValidationError


load_dotenv()
load_dotenv(Path(__file__).parent / ".venv" / ".env")

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:3b")
OLLAMA_TIMEOUT_SECONDS = 180

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
    """Raised when the local Ollama service cannot return usable structured output."""


def _request_ollama(messages: list[dict[str, str]]) -> AssistantOutput:
    request = Request(
        f"{OLLAMA_HOST}/api/chat",
        data=json.dumps(
            {
                "model": OLLAMA_MODEL,
                "messages": messages,
                "stream": False,
                "format": AssistantOutput.model_json_schema(),
                "options": {
                    "num_ctx": 2048,
                    "num_predict": 128,
                },
            }
        ).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urlopen(request, timeout=OLLAMA_TIMEOUT_SECONDS) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        detail = exc.read(500).decode("utf-8", errors="replace").strip()
        raise AIHandlerError(
            f"Ollama returned HTTP {exc.code}: {detail or exc.reason}"
        ) from exc
    except (URLError, TimeoutError, OSError) as exc:
        raise AIHandlerError(
            f"Could not reach Ollama at {OLLAMA_HOST}. "
            "Check that Ollama is running and the configured host is correct."
        ) from exc
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AIHandlerError("Ollama returned an invalid JSON response.") from exc

    if not isinstance(payload, dict):
        raise AIHandlerError("Ollama returned an unexpected response format.")

    message = payload.get("message")
    if not isinstance(message, dict) or not isinstance(message.get("content"), str):
        raise AIHandlerError("Ollama response did not contain message content.")

    try:
        return AssistantOutput.model_validate_json(message["content"])
    except (ValidationError, json.JSONDecodeError) as exc:
        raise AIHandlerError(
            "Ollama response did not match the required reply and telemetry schema."
        ) from exc


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
    return await asyncio.to_thread(_request_ollama, messages)
