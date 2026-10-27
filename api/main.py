import asyncio
import csv
import json
import logging
import os
import re
import secrets
import uuid
from datetime import UTC, datetime
from io import StringIO
from dotenv import load_dotenv
from typing import Literal, TypedDict
from urllib.parse import urlsplit, urlunsplit

load_dotenv()
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import PlainTextResponse, Response
from pydantic import BaseModel, Field, model_validator

from backend import ai_handler as backend_ai_handler
from backend.classifier import (
    ScamClassifierEngine,
    ScamClassifierResult,
    check_and_notify_high_risk,
)
from backend import database as backend_database
from backend import link_checker
from backend import scam_feed
from backend.personas import PERSONAS
from backend.whatsapp_client import WhatsAppClientError, send_whatsapp_message
import database


logger = logging.getLogger(__name__)

_DOMAIN_PATTERN = re.compile(
    r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z]{2,63}",
    re.IGNORECASE,
)
_BITCOIN_WALLET_PATTERN = re.compile(
    r"(?<![A-Za-z0-9])(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|"
    r"bc1[ac-hj-np-z02-9]{11,71})(?![A-Za-z0-9])",
    re.IGNORECASE,
)
_ETHEREUM_WALLET_PATTERN = re.compile(
    r"(?<![A-Za-z0-9])0x[a-fA-F0-9]{40}(?![A-Za-z0-9])"
)


class ExportIndicator(TypedDict):
    type: str
    value: str
    scam_stage_tags: list[str]
    observed_at: list[str]


class LinkCheckRequest(BaseModel):
    url: str = Field(min_length=1, max_length=2048)


class LinkCheckResponse(BaseModel):
    verdict: Literal["known_threat", "no_known_threat", "not_configured"]
    message: str
    source: str | None
    checked_at: str | None
    threat_types: list[str]


class WhatsAppWebhookRequest(BaseModel):
    chat_id: str | None = Field(default=None, min_length=1, max_length=256)
    incoming_text: str | None = Field(default=None, min_length=1, max_length=10_000)
    sender_id: str | None = Field(default=None, min_length=1, max_length=256)
    message_text: str | None = Field(default=None, min_length=1, max_length=10_000)

    @model_validator(mode="after")
    def validate_message_fields(self) -> "WhatsAppWebhookRequest":
        if not (self.chat_id or self.sender_id):
            raise ValueError("chat_id is required")
        if not (self.incoming_text or self.message_text):
            raise ValueError("incoming_text is required")
        return self

    @property
    def resolved_chat_id(self) -> str:
        return self.chat_id or self.sender_id or ""

    @property
    def resolved_incoming_text(self) -> str:
        return self.incoming_text or self.message_text or ""


class WhatsAppTextPayload(BaseModel):
    body: str


class WhatsAppChatMessagePayload(BaseModel):
    messaging_product: str = "whatsapp"
    to: str
    type: str = "text"
    text: WhatsAppTextPayload
    reply: str
    status: Literal["auto_reply", "pending_review", "manual_takeover"]
    pending_reply_id: int | None = None
    scam_score: int
    is_scam: bool
    detected_flags: list[str] = Field(default_factory=list)
    manual_mode: bool = False


class DemoChatResponse(BaseModel):
    reply: str
    status: Literal["simulated", "pending_review", "manual_takeover"]
    pending_reply_id: int | None = None
    scam_score: int
    is_scam: bool
    detected_flags: list[str] = Field(default_factory=list)
    manual_mode: bool = False


class PersonaCompareRequest(BaseModel):
    message_text: str = Field(min_length=1, max_length=3000)


class PersonaCompareResult(BaseModel):
    persona_id: str
    name: str
    location: str
    occupation: str
    reply: str
    scam_stage: str
    pressure_level: int | None


class PersonaCompareResponse(BaseModel):
    message_text: str
    results: list[PersonaCompareResult]
    saved_to_history: bool = False


class TelemetryResponse(BaseModel):
    scam_stage: str | None
    pressure_level: int | None
    delay_strategy: str | None = None
    notes: str | None = None
    extracted_artifacts: list[str] = Field(default_factory=list)


class ConversationMessageResponse(BaseModel):
    role: str
    content: str
    created_at: str
    telemetry: TelemetryResponse | None
    scam_score: int | None = None
    is_scam: bool = False
    detected_flags: list[str] = Field(default_factory=list)


class ConversationArtifactResponse(BaseModel):
    id: int
    artifact_type: str
    artifact_value: str
    extracted_at: str


class PendingReplyResponse(BaseModel):
    id: int
    response_text: str
    scam_stage: str | None
    pressure_level: int | None
    created_at: str


class ConversationResponse(BaseModel):
    sender_id: str
    persona_id: str | None
    is_auto_reply: bool
    manual_mode: bool = False
    messages: list[ConversationMessageResponse]
    pending_replies: list[PendingReplyResponse]
    artifacts: list[ConversationArtifactResponse]


class PersonaAssignmentRequest(BaseModel):
    chat_id: str = Field(min_length=1, max_length=256)
    persona_id: str = Field(min_length=1)


class PersonaAssignmentResponse(BaseModel):
    chat_id: str
    persona_id: str


class AutoReplySettingRequest(BaseModel):
    chat_id: str = Field(min_length=1, max_length=256)
    is_auto_reply: bool


class AutoReplySettingResponse(BaseModel):
    chat_id: str
    is_auto_reply: bool


class TakeoverSettingRequest(BaseModel):
    chat_id: str = Field(min_length=1, max_length=256)
    manual_mode: bool


class TakeoverSettingResponse(BaseModel):
    chat_id: str
    manual_mode: bool


class ApprovePendingReplyRequest(BaseModel):
    edited_text: str = Field(min_length=1, max_length=10_000)


class PendingReplyApprovalResponse(BaseModel):
    id: int
    status: Literal["approved"]


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncGenerator[None, None]:
    await asyncio.to_thread(database.initialize_database)
    await asyncio.to_thread(backend_database.init_db)
    try:
        await asyncio.to_thread(scam_feed.fetch_latest_sg_scam_keywords)
    except scam_feed.ScamFeedError as exc:
        logger.error("Initial scam-advisory refresh failed: %s", exc)

    refresh_task = asyncio.create_task(_refresh_scam_keywords_periodically())
    try:
        yield
    finally:
        refresh_task.cancel()
        try:
            await refresh_task
        except asyncio.CancelledError:
            pass


async def _refresh_scam_keywords_periodically() -> None:
    while True:
        await asyncio.sleep(scam_feed.FEED_REFRESH_INTERVAL_SECONDS)
        try:
            await asyncio.to_thread(scam_feed.fetch_latest_sg_scam_keywords)
        except scam_feed.ScamFeedError as exc:
            logger.error("Periodic scam-advisory refresh failed: %s", exc)


app = FastAPI(title="Honeypot Research API", lifespan=lifespan)
app.frontend("/", directory=Path(__file__).resolve().parent.parent / "frontend")


@app.get("/api/analytics")
async def get_analytics() -> dict[str, object]:
    return await asyncio.to_thread(backend_database.get_research_analytics)


@app.get("/api/scam-feed/status")
async def get_scam_feed_status() -> dict[str, str | bool | int | None]:
    return scam_feed.get_feed_status()


@app.get("/api/model/status")
async def get_model_status() -> dict[str, str | bool]:
    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    configured = bool(os.getenv("OPENAI_API_KEY", "").strip())
    return {
        "provider": "openai",
        "display_name": "OpenAI",
        "model": model,
        "is_local": False,
        "configured": configured,
        "singlish_mode": True,
        "detail": (
            "Conversation text is processed by the configured OpenAI service."
            if configured
            else "OpenAI is not configured; generated replies are unavailable."
        ),
    }


@app.get("/api/personas")
async def get_personas() -> list[dict[str, str]]:
    return [
        {
            "persona_id": persona.persona_id,
            "name": persona.name,
            "location": persona.location,
            "occupation": persona.occupation,
            "profile_description": persona.profile_description,
            "response_style": persona.response_style,
            "scammer_adjustment_cues": persona.scammer_adjustment_cues,
        }
        for persona in PERSONAS.values()
    ]


@app.post("/api/personas/compare", response_model=PersonaCompareResponse)
async def compare_persona_responses(
    request: PersonaCompareRequest,
) -> PersonaCompareResponse:
    history = [{"role": "user", "content": request.message_text}]
    personas = list(PERSONAS.values())
    try:
        responses = await asyncio.gather(
            *(
                backend_ai_handler.generate_persona_response(
                    persona.persona_id, history
                )
                for persona in personas
            )
        )
    except backend_ai_handler.AIHandlerError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Could not compare persona responses: {exc}",
        ) from exc

    results = []
    for persona, (reply, telemetry) in zip(personas, responses):
        pressure = telemetry.get("scammer_pressure_level")
        results.append(
            PersonaCompareResult(
                persona_id=persona.persona_id,
                name=persona.name,
                location=persona.location,
                occupation=persona.occupation,
                reply=reply,
                scam_stage=str(telemetry.get("current_scam_stage") or "unknown"),
                pressure_level=pressure if isinstance(pressure, int) else None,
            )
        )
    return PersonaCompareResponse(
        message_text=request.message_text,
        results=results,
    )


@app.post("/api/link-check", response_model=LinkCheckResponse)
async def check_link(request: LinkCheckRequest) -> LinkCheckResponse:
    try:
        result = await link_checker.check_url(request.url)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except link_checker.LinkCheckError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    return LinkCheckResponse(**result)


@app.post("/api/persona/assign", response_model=PersonaAssignmentResponse)
async def assign_chat_persona(
    request: PersonaAssignmentRequest,
) -> PersonaAssignmentResponse:
    try:
        await asyncio.to_thread(
            backend_database.assign_persona, request.chat_id, request.persona_id
        )
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return PersonaAssignmentResponse(
        chat_id=request.chat_id,
        persona_id=request.persona_id,
    )


def _normalize_domain(value: str) -> str | None:
    candidate = value.strip().rstrip(".").lower()
    try:
        candidate = candidate.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    return candidate if _DOMAIN_PATTERN.fullmatch(candidate) else None


def _normalize_url(value: str) -> tuple[str, str] | None:
    try:
        parsed = urlsplit(value.strip())
        hostname = parsed.hostname
        if parsed.scheme.lower() not in {"http", "https"} or hostname is None:
            return None
        domain = _normalize_domain(hostname)
        if domain is None:
            return None
        port = parsed.port
    except ValueError:
        return None

    netloc = domain if port is None else f"{domain}:{port}"
    sanitized_url = urlunsplit(
        (parsed.scheme.lower(), netloc, parsed.path, "", "")
    )
    return sanitized_url, domain


def _build_export_indicators(
    records: list[dict[str, object]],
) -> list[ExportIndicator]:
    indicators: dict[tuple[str, str], ExportIndicator] = {}

    def add_indicator(
        kind: str,
        value: str,
        stage: object,
        observed_at: object,
    ) -> None:
        key = (kind, value)
        indicator = indicators.setdefault(
            key,
            {
                "type": kind,
                "value": value,
                "scam_stage_tags": [],
                "observed_at": [],
            },
        )
        if (
            isinstance(stage, str)
            and stage.strip()
            and stage.strip().lower() != "unknown"
            and stage.strip() not in indicator["scam_stage_tags"]
        ):
            indicator["scam_stage_tags"].append(stage.strip())
        if (
            isinstance(observed_at, str)
            and observed_at
            and observed_at not in indicator["observed_at"]
        ):
            indicator["observed_at"].append(observed_at)

    for record in records:
        artifact_type = str(record.get("artifact_type") or "").strip().lower()
        value = str(record.get("artifact_value") or "").strip()
        if not value:
            continue

        url_data = _normalize_url(value)
        if url_data is not None and (
            "url" in artifact_type
            or "link" in artifact_type
            or value.lower().startswith(("http://", "https://"))
        ):
            sanitized_url, hostname = url_data
            add_indicator(
                "url",
                sanitized_url,
                record.get("scam_stage"),
                record.get("extracted_at"),
            )
            add_indicator(
                "domain",
                hostname,
                record.get("scam_stage"),
                record.get("extracted_at"),
            )

        domain = _normalize_domain(value)
        if domain is not None and any(
            marker in artifact_type for marker in ("domain", "hostname", "host")
        ):
            add_indicator(
                "domain",
                domain,
                record.get("scam_stage"),
                record.get("extracted_at"),
            )

        wallet_match = (
            _BITCOIN_WALLET_PATTERN.search(value)
            or _ETHEREUM_WALLET_PATTERN.search(value)
        )
        if wallet_match is not None and any(
            marker in artifact_type
            for marker in ("wallet", "crypto", "bitcoin", "ethereum")
        ):
            add_indicator(
                "crypto-wallet",
                wallet_match.group(),
                record.get("scam_stage"),
                record.get("extracted_at"),
            )

    return sorted(
        indicators.values(),
        key=lambda item: (str(item["type"]), str(item["value"])),
    )


def _build_stix_bundle(
    indicators: list[ExportIndicator],
) -> dict[str, object]:
    timestamp = datetime.now(UTC).isoformat(timespec="seconds").replace("+00:00", "Z")
    objects: list[dict[str, object]] = []
    stix_object_types = {
        "url": "url",
        "domain": "domain-name",
        "crypto-wallet": "x-phishlens-crypto-wallet",
    }
    for indicator in indicators:
        indicator_type = str(indicator["type"])
        indicator_value = str(indicator["value"])
        escaped_value = indicator_value.replace("\\", "\\\\").replace("'", "\\'")
        stages = indicator["scam_stage_tags"]
        labels = ["phishing", "malicious-activity"]
        labels.extend(
            f"scam-stage:{re.sub(r'[^a-z0-9-]+', '-', stage.lower()).strip('-')}"
            for stage in stages
            if isinstance(stage, str) and stage.strip()
        )
        objects.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{uuid.uuid4()}",
                "created": timestamp,
                "modified": timestamp,
                "name": f"PhishLab {indicator_type} indicator",
                "description": (
                    "An extracted research artifact. Associated scam stage tags "
                    "are unverified model assessments."
                ),
                "pattern": (
                    f"[{stix_object_types[indicator_type]}:value = "
                    f"'{escaped_value}']"
                ),
                "pattern_type": "stix",
                "valid_from": timestamp,
                "labels": labels,
                "x_phishlens_scam_stage_tags": stages,
                "x_phishlens_observed_at": indicator["observed_at"],
            }
        )
    return {
        "type": "bundle",
        "id": f"bundle--{uuid.uuid4()}",
        "objects": objects,
    }


@app.get("/api/export/artifacts")
async def export_threat_artifacts(
    format: Literal["json", "stix"] = "json",
) -> Response:
    records = await asyncio.to_thread(
        backend_database.get_threat_artifacts_for_export
    )
    indicators = _build_export_indicators(records)
    if format == "stix":
        payload: dict[str, object] = _build_stix_bundle(indicators)
    else:
        payload = {
            "schema": "phishlens-threat-artifacts/v1",
            "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "indicator_count": len(indicators),
            "indicators": indicators,
        }
    return Response(
        content=json.dumps(payload, ensure_ascii=False, indent=2),
        media_type="application/json",
        headers={
            "Content-Disposition": (
                'attachment; filename="scam_indicators_export.json"'
            )
        },
    )


@app.get("/api/artifacts/export")
async def export_artifacts(
    format: Literal["json", "csv"] = "json",
) -> Response:
    artifacts = await asyncio.to_thread(backend_database.get_artifacts_for_export)
    if format == "json":
        return Response(
            content=json.dumps(artifacts),
            media_type="application/json",
            headers={"Content-Disposition": 'attachment; filename="scam-artifacts.json"'},
        )

    output = StringIO(newline="")
    fieldnames = ["id", "chat_id", "artifact_type", "artifact_value", "extracted_at"]
    writer = csv.DictWriter(output, fieldnames=fieldnames)
    writer.writeheader()
    for artifact in artifacts:
        safe_artifact = artifact.copy()
        for field in fieldnames:
            value = str(safe_artifact[field])
            if value.lstrip().startswith(("=", "+", "-", "@", "\t", "\r")):
                value = f"'{value}"
            safe_artifact[field] = value
        writer.writerow(safe_artifact)
    return Response(
        content=output.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="scam-artifacts.csv"'},
    )


@app.get("/conversation/{sender_id}", response_model=ConversationResponse)
@app.get("/api/conversations/{sender_id}", response_model=ConversationResponse)
async def get_conversation(sender_id: str) -> ConversationResponse:
    data = await asyncio.to_thread(
        backend_database.get_research_conversation, sender_id
    )
    return ConversationResponse(**data)


@app.put("/api/conversations/auto-reply", response_model=AutoReplySettingResponse)
async def set_conversation_auto_reply(
    request: AutoReplySettingRequest,
) -> AutoReplySettingResponse:
    await asyncio.to_thread(
        backend_database.set_auto_reply, request.chat_id, request.is_auto_reply
    )
    return AutoReplySettingResponse(
        chat_id=request.chat_id,
        is_auto_reply=request.is_auto_reply,
    )


@app.post(
    "/api/conversation/toggle-takeover",
    response_model=TakeoverSettingResponse,
)
async def toggle_conversation_takeover(
    request: TakeoverSettingRequest,
) -> TakeoverSettingResponse:
    await asyncio.to_thread(
        backend_database.set_manual_mode,
        request.chat_id,
        request.manual_mode,
    )
    return TakeoverSettingResponse(
        chat_id=request.chat_id,
        manual_mode=request.manual_mode,
    )


@app.post(
    "/api/pending-replies/{reply_id}/approve",
    response_model=PendingReplyApprovalResponse,
)
async def approve_pending_reply(
    reply_id: int,
    request: ApprovePendingReplyRequest,
) -> PendingReplyApprovalResponse:
    approved = await asyncio.to_thread(
        backend_database.approve_pending_reply, reply_id, request.edited_text
    )
    if not approved:
        raise HTTPException(
            status_code=404,
            detail="Pending reply not found or already reviewed",
        )
    return PendingReplyApprovalResponse(id=reply_id, status="approved")


@app.get("/webhook/whatsapp", response_class=PlainTextResponse)
async def verify_whatsapp_webhook(
    mode: str | None = Query(default=None, alias="hub.mode"),
    verify_token: str | None = Query(default=None, alias="hub.verify_token"),
    challenge: str | None = Query(default=None, alias="hub.challenge"),
) -> PlainTextResponse:
    expected_token = os.getenv("WHATSAPP_VERIFY_TOKEN")
    if expected_token is None:
        raise HTTPException(
            status_code=503,
            detail="WhatsApp webhook verification is not configured",
        )
    if (
        mode != "subscribe"
        or verify_token is None
        or challenge is None
        or not secrets.compare_digest(verify_token, expected_token)
    ):
        raise HTTPException(status_code=403, detail="Webhook verification failed")
    return PlainTextResponse(challenge)


async def process_chat_message(
    chat_id: str,
    incoming_text: str,
    *,
    deliver_via_whatsapp: bool,
) -> tuple[str, bool, int | None, ScamClassifierResult, bool]:
    stored_history = await asyncio.to_thread(
        backend_database.get_chat_history, chat_id
    )
    history = [
        {
            "role": "user" if message["sender"] == "scammer" else "assistant",
            "content": message["message_text"],
        }
        for message in stored_history
    ]
    history.append({"role": "user", "content": incoming_text})
    classifier_result = ScamClassifierEngine.analyze(history)
    score = classifier_result["scam_score"]
    detected_flags = classifier_result["detected_flags"]
    high_risk_alert = check_and_notify_high_risk(
        chat_id,
        score,
        detected_flags,
    )
    if high_risk_alert is not None:
        await asyncio.to_thread(
            backend_database.log_event,
            "CRITICAL",
            json.dumps(high_risk_alert, separators=(",", ":")),
            chat_id,
        )
    await asyncio.to_thread(
        backend_database.save_message,
        chat_id,
        "scammer",
        incoming_text,
        scam_score=score,
        detected_flags=detected_flags,
    )
    incoming_message_id = await asyncio.to_thread(
        database.save_message, chat_id, "incoming", incoming_text
    )

    async def manual_takeover_result() -> tuple[
        str,
        bool,
        int | None,
        ScamClassifierResult,
        bool,
    ]:
        await asyncio.to_thread(
            database.save_telemetry,
            message_id=incoming_message_id,
            sender_id=chat_id,
            scam_stage="manual_takeover",
            pressure_level="unknown",
            extracted_artifacts=[],
            delay_strategy="none",
            notes="Manual takeover is active; no automated reply was generated.",
        )
        return "", False, None, classifier_result, True

    if await asyncio.to_thread(backend_database.get_manual_mode, chat_id):
        return await manual_takeover_result()

    stored_history = await asyncio.to_thread(
        backend_database.get_chat_history, chat_id
    )
    history = [
        {
            "role": "user" if message["sender"] == "scammer" else "assistant",
            "content": message["message_text"],
        }
        for message in stored_history
    ]

    try:
        response_text, log_data = await backend_ai_handler.generate_honeypot_response(
            chat_id,
            history
        )
    except backend_ai_handler.AIHandlerError as exc:
        await asyncio.to_thread(
            database.save_telemetry,
            message_id=incoming_message_id,
            sender_id=chat_id,
            scam_stage="unknown",
            pressure_level="unknown",
            extracted_artifacts=[],
            delay_strategy="none",
            notes=f"AI response unavailable: {exc}",
        )
        raise HTTPException(
            status_code=502,
            detail=str(exc),
        ) from exc

    if await asyncio.to_thread(backend_database.get_manual_mode, chat_id):
        return await manual_takeover_result()

    stage = log_data.get("current_scam_stage")
    pressure = log_data.get("scammer_pressure_level")
    artifacts = log_data.get("scam_artifacts_extracted", [])

    is_auto_reply = await asyncio.to_thread(backend_database.get_auto_reply, chat_id)
    pending_reply_id = None
    if is_auto_reply:
        if deliver_via_whatsapp:
            if await asyncio.to_thread(
                backend_database.get_manual_mode,
                chat_id,
            ):
                return await manual_takeover_result()
            try:
                await send_whatsapp_message(chat_id, response_text)
            except WhatsAppClientError as exc:
                raise HTTPException(
                    status_code=502,
                    detail=str(exc),
                ) from exc
        await asyncio.to_thread(
            backend_database.save_message,
            chat_id,
            "bot",
            response_text,
            stage=stage if isinstance(stage, str) else None,
            pressure=pressure if isinstance(pressure, int) else None,
            delay_strategy=str(log_data.get("delay_strategy", "none")),
            notes=str(log_data.get("notes", "")),
            extracted_artifacts=[
                item for item in artifacts if isinstance(item, str)
            ] if isinstance(artifacts, list) else [],
        )
    else:
        pending_reply_id = await asyncio.to_thread(
            backend_database.save_pending_reply,
            chat_id,
            response_text,
            stage=stage if isinstance(stage, str) else None,
            pressure=pressure if isinstance(pressure, int) else None,
        )
    if isinstance(artifacts, list) and artifacts:
        await asyncio.to_thread(backend_database.save_artifacts, chat_id, artifacts)

    reply_message_id = incoming_message_id
    if is_auto_reply:
        reply_message_id = await asyncio.to_thread(
            database.save_message, chat_id, "reply", response_text
        )
    await asyncio.to_thread(
        database.save_telemetry,
        message_id=reply_message_id,
        sender_id=chat_id,
        scam_stage=str(stage or "unknown"),
        pressure_level=str(pressure if pressure is not None else "unknown"),
        extracted_artifacts=artifacts if isinstance(artifacts, list) else [],
        delay_strategy=str(log_data.get("delay_strategy", "none")),
        notes=str(log_data.get("notes", "")),
    )

    return response_text, is_auto_reply, pending_reply_id, classifier_result, False


@app.post("/api/demo/chat", response_model=DemoChatResponse)
async def demo_chat(request: WhatsAppWebhookRequest) -> DemoChatResponse:
    (
        response_text,
        is_auto_reply,
        pending_reply_id,
        classifier_result,
        manual_mode,
    ) = await process_chat_message(
        request.resolved_chat_id,
        request.resolved_incoming_text,
        deliver_via_whatsapp=False,
    )
    return DemoChatResponse(
        reply=response_text if is_auto_reply else "",
        status=(
            "manual_takeover"
            if manual_mode
            else "simulated" if is_auto_reply else "pending_review"
        ),
        pending_reply_id=pending_reply_id,
        scam_score=classifier_result["scam_score"],
        is_scam=classifier_result["is_scam"],
        detected_flags=classifier_result["detected_flags"],
        manual_mode=manual_mode,
    )




@app.post(
    "/webhook/whatsapp",
    response_model=WhatsAppChatMessagePayload,
)
async def whatsapp_webhook(
    request: WhatsAppWebhookRequest,
) -> WhatsAppChatMessagePayload:
    chat_id = request.resolved_chat_id
    (
        response_text,
        is_auto_reply,
        pending_reply_id,
        classifier_result,
        manual_mode,
    ) = await process_chat_message(
        chat_id,
        request.resolved_incoming_text,
        deliver_via_whatsapp=True,
    )
    return WhatsAppChatMessagePayload(
        to=chat_id,
        text=WhatsAppTextPayload(body=response_text if is_auto_reply else ""),
        reply=response_text if is_auto_reply else "",
        status=(
            "manual_takeover"
            if manual_mode
            else "auto_reply" if is_auto_reply else "pending_review"
        ),
        pending_reply_id=pending_reply_id,
        scam_score=classifier_result["scam_score"],
        is_scam=classifier_result["is_scam"],
        detected_flags=classifier_result["detected_flags"],
        manual_mode=manual_mode,
    )
