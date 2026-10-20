from contextlib import asynccontextmanager
from uuid import uuid4

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from backend import ai_handler, database


class ChatRequest(BaseModel):
    message: str = Field(min_length=1)
    conversation_id: str | None = None


class ChatResponse(BaseModel):
    conversation_id: str
    response: str


@asynccontextmanager
async def lifespan(_: FastAPI):
    database.initialize_database()
    yield


app = FastAPI(title="Romance-Scam API", lifespan=lifespan)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest) -> ChatResponse:
    conversation_id = request.conversation_id or str(uuid4())
    database.log_event("INFO", "Chat request received", conversation_id)
    database.save_message(conversation_id, "scammer", request.message)

    try:
        stored_history = database.get_chat_history(conversation_id)
        history = [
            {
                "role": "user" if item["sender"] == "scammer" else "assistant",
                "content": item["message_text"],
            }
            for item in stored_history
        ]
        response_text, log_data = await ai_handler.generate_honeypot_response(
            conversation_id,
            history,
        )
    except ai_handler.AIHandlerError as exc:
        database.log_event("ERROR", f"LLM request failed: {exc}", conversation_id)
        raise HTTPException(
            status_code=502,
            detail=str(exc),
        ) from exc

    stage = log_data.get("current_scam_stage")
    pressure = log_data.get("scammer_pressure_level")
    artifacts = log_data.get("scam_artifacts_extracted", [])
    database.save_message(
        conversation_id,
        "bot",
        response_text,
        stage=stage if isinstance(stage, str) else None,
        pressure=pressure if isinstance(pressure, int) else None,
    )
    if isinstance(artifacts, list) and artifacts:
        database.save_artifacts(conversation_id, artifacts)
    database.log_event("INFO", "Chat response generated", conversation_id)
    return ChatResponse(
        conversation_id=conversation_id,
        response=response_text,
    )
