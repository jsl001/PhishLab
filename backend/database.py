import json
import os
from collections.abc import Mapping, Sequence
from contextlib import closing
from pathlib import Path
from typing import Any

from backend.classifier import SCAM_REVIEW_THRESHOLD
from backend.db import (
    DatabaseConnection,
    connect,
    display_timestamp,
    identity_primary_key,
    is_postgres,
)
from backend.personas import DEFAULT_PERSONA_ID, get_persona


DB_PATH = os.getenv("DATABASE_PATH", "./data/honeypot.db")
DATABASE_PATH = Path(DB_PATH)


def _connect() -> DatabaseConnection:
    return connect(DATABASE_PATH)


def init_db() -> None:
    with closing(_connect()) as connection:
        with connection:
            connection.execute(
                f"""
                CREATE TABLE IF NOT EXISTS conversations (
                    id {identity_primary_key(connection)},
                    chat_id TEXT NOT NULL,
                    sender TEXT NOT NULL CHECK (sender IN ('scammer', 'bot')),
                    message_text TEXT NOT NULL,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    scam_stage TEXT,
                    pressure_level INTEGER,
                    delay_strategy TEXT,
                    notes TEXT,
                    extracted_artifacts TEXT NOT NULL DEFAULT '[]',
                    scam_score INTEGER,
                    detected_flags TEXT NOT NULL DEFAULT '[]'
                )
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_conversations_chat_id
                ON conversations (chat_id, id)
                """
            )
            connection.execute(
                f"""
                CREATE TABLE IF NOT EXISTS scam_artifacts (
                    id {identity_primary_key(connection)},
                    chat_id TEXT NOT NULL,
                    artifact_type TEXT NOT NULL,
                    artifact_value TEXT NOT NULL,
                    extracted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS chat_personas (
                    chat_id TEXT PRIMARY KEY,
                    persona_id TEXT NOT NULL
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS chat_settings (
                    chat_id TEXT PRIMARY KEY,
                    is_auto_reply INTEGER NOT NULL DEFAULT 1
                        CHECK (is_auto_reply IN (0, 1)),
                    manual_mode INTEGER NOT NULL DEFAULT 0
                        CHECK (manual_mode IN (0, 1))
                )
                """
            )
            connection.execute(
                f"""
                CREATE TABLE IF NOT EXISTS pending_replies (
                    id {identity_primary_key(connection)},
                    chat_id TEXT NOT NULL,
                    response_text TEXT NOT NULL,
                    scam_stage TEXT,
                    pressure_level INTEGER,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status TEXT NOT NULL DEFAULT 'pending'
                        CHECK (status IN ('pending', 'approved'))
                )
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_pending_replies_chat_status
                ON pending_replies (chat_id, status, id)
                """
            )

            # Keep the original backend API working while it is migrated to
            # the conversations and scam_artifacts tables.
            connection.execute(
                f"""
                CREATE TABLE IF NOT EXISTS chat_history (
                    id {identity_primary_key(connection)},
                    conversation_id TEXT NOT NULL,
                    role TEXT NOT NULL CHECK (role IN ('user', 'assistant')),
                    content TEXT NOT NULL,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_chat_history_conversation
                ON chat_history (conversation_id, id)
                """
            )
            connection.execute(
                f"""
                CREATE TABLE IF NOT EXISTS application_logs (
                    id {identity_primary_key(connection)},
                    level TEXT NOT NULL,
                    message TEXT NOT NULL,
                    conversation_id TEXT,
                    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )


def get_auto_reply(chat_id: str) -> bool:
    with closing(_connect()) as connection:
        row = connection.execute(
            "SELECT is_auto_reply FROM chat_settings WHERE chat_id = ?",
            (chat_id,),
        ).fetchone()
    return True if row is None else bool(row[0])


def set_auto_reply(chat_id: str, is_auto_reply: bool) -> None:
    if not isinstance(is_auto_reply, bool):
        raise TypeError("is_auto_reply must be a boolean")
    with closing(_connect()) as connection:
        with connection:
            connection.execute(
                """
                INSERT INTO chat_settings (chat_id, is_auto_reply)
                VALUES (?, ?)
                ON CONFLICT(chat_id) DO UPDATE
                SET is_auto_reply = excluded.is_auto_reply
                """,
                (chat_id, int(is_auto_reply)),
            )


def get_manual_mode(chat_id: str) -> bool:
    with closing(_connect()) as connection:
        row = connection.execute(
            "SELECT manual_mode FROM chat_settings WHERE chat_id = ?",
            (chat_id,),
        ).fetchone()
    return False if row is None else bool(row[0])


def set_manual_mode(chat_id: str, manual_mode: bool) -> None:
    if not isinstance(manual_mode, bool):
        raise TypeError("manual_mode must be a boolean")
    with closing(_connect()) as connection:
        with connection:
            connection.execute(
                """
                INSERT INTO chat_settings (chat_id, manual_mode)
                VALUES (?, ?)
                ON CONFLICT(chat_id) DO UPDATE
                SET manual_mode = excluded.manual_mode
                """,
                (chat_id, int(manual_mode)),
            )


def save_pending_reply(
    chat_id: str,
    response_text: str,
    stage: str | None = None,
    pressure: int | None = None,
) -> int:
    with closing(_connect()) as connection:
        with connection:
            cursor = connection.execute(
                """
                INSERT INTO pending_replies (
                    chat_id, response_text, scam_stage, pressure_level
                )
                VALUES (?, ?, ?, ?)
                RETURNING id
                """,
                (chat_id, response_text, stage, pressure),
            )
            row = cursor.fetchone()
            pending_reply_id = None if row is None else int(row[0])
    if pending_reply_id is None:
        raise RuntimeError("Database did not return an id for the pending reply")
    return pending_reply_id


def get_pending_replies(chat_id: str) -> list[dict[str, Any]]:
    with closing(_connect()) as connection:
        rows = connection.execute(
            """
            SELECT id, response_text, scam_stage, pressure_level, created_at
            FROM pending_replies
            WHERE chat_id = ? AND status = 'pending'
            ORDER BY id
            """,
            (chat_id,),
        ).fetchall()
    keys = ("id", "response_text", "scam_stage", "pressure_level", "created_at")
    results = [dict(zip(keys, row)) for row in rows]
    for result in results:
        result["created_at"] = display_timestamp(result["created_at"])
    return results


def approve_pending_reply(reply_id: int, edited_text: str) -> bool:
    with closing(_connect()) as connection:
        with connection:
            row = connection.execute(
                """
                SELECT chat_id, scam_stage, pressure_level
                FROM pending_replies
                WHERE id = ? AND status = 'pending'
                """,
                (reply_id,),
            ).fetchone()
            if row is None:
                return False
            chat_id, stage, pressure = row
            cursor = connection.execute(
                """
                UPDATE pending_replies
                SET response_text = ?, status = 'approved'
                WHERE id = ? AND status = 'pending'
                """,
                (edited_text, reply_id),
            )
            if cursor.rowcount != 1:
                return False
            connection.execute(
                """
                INSERT INTO conversations (
                    chat_id, sender, message_text, scam_stage, pressure_level
                )
                VALUES (?, 'bot', ?, ?, ?)
                """,
                (chat_id, edited_text, stage, pressure),
            )
            connection.execute(
                """
                INSERT INTO chat_history (conversation_id, role, content)
                VALUES (?, 'assistant', ?)
                """,
                (chat_id, edited_text),
            )
    return True


def assign_persona(chat_id: str, persona_id: str) -> None:
    get_persona(persona_id)
    with closing(_connect()) as connection:
        with connection:
            connection.execute(
                """
                INSERT INTO chat_personas (chat_id, persona_id)
                VALUES (?, ?)
                ON CONFLICT(chat_id) DO UPDATE SET persona_id = excluded.persona_id
                """,
                (chat_id, persona_id),
            )


def get_or_assign_persona(
    chat_id: str,
    default_persona_id: str = DEFAULT_PERSONA_ID,
) -> str:
    get_persona(default_persona_id)
    with closing(_connect()) as connection:
        with connection:
            connection.execute(
                """
                INSERT INTO chat_personas (chat_id, persona_id)
                VALUES (?, ?)
                ON CONFLICT (chat_id) DO NOTHING
                """,
                (chat_id, default_persona_id),
            )
            row = connection.execute(
                "SELECT persona_id FROM chat_personas WHERE chat_id = ?",
                (chat_id,),
            ).fetchone()
    if row is None:
        raise RuntimeError(f"Could not assign a persona to chat {chat_id!r}")
    return str(row[0])


def save_message(
    chat_id: str,
    sender: str,
    text: str,
    stage: str | None = None,
    pressure: int | None = None,
    delay_strategy: str | None = None,
    notes: str | None = None,
    extracted_artifacts: list[str] | None = None,
    scam_score: int | None = None,
    detected_flags: list[str] | None = None,
) -> int:
    legacy_role = {"user": "user", "assistant": "assistant"}.get(sender)
    normalized_sender = {"user": "scammer", "assistant": "bot"}.get(sender, sender)
    if normalized_sender not in {"scammer", "bot"}:
        raise ValueError("sender must be 'scammer' or 'bot'")
    if pressure is not None and not isinstance(pressure, int):
        raise TypeError("pressure must be an integer or None")
    if scam_score is not None:
        if isinstance(scam_score, bool) or not isinstance(scam_score, int):
            raise TypeError("scam_score must be an integer or None")
        if not 0 <= scam_score <= 100:
            raise ValueError("scam_score must be between 0 and 100")
    if detected_flags is not None and not all(
        isinstance(flag, str) for flag in detected_flags
    ):
        raise TypeError("detected_flags must contain only strings")

    with closing(_connect()) as connection:
        with connection:
            cursor = connection.execute(
                """
                INSERT INTO conversations (
                    chat_id, sender, message_text, scam_stage, pressure_level,
                    delay_strategy, notes, extracted_artifacts, scam_score,
                    detected_flags
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                RETURNING id
                """,
                (
                    chat_id,
                    normalized_sender,
                    text,
                    stage,
                    pressure,
                    delay_strategy,
                    notes,
                    json.dumps(extracted_artifacts or []),
                    scam_score,
                    json.dumps(detected_flags or []),
                ),
            )
            row = cursor.fetchone()
            message_id = None if row is None else int(row[0])
            if legacy_role is not None:
                connection.execute(
                    """
                    INSERT INTO chat_history (conversation_id, role, content)
                    VALUES (?, ?, ?)
                    """,
                    (chat_id, legacy_role, text),
                )
    if message_id is None:
        raise RuntimeError("Database did not return an id for the saved message")
    return message_id


def conversation_message_exists(chat_id: str, sender: str, text: str) -> bool:
    """Return whether this exact inbound message is already in a thread."""
    normalized_sender = {"user": "scammer", "assistant": "bot"}.get(sender, sender)
    with closing(_connect()) as connection:
        row = connection.execute(
            """
            SELECT 1
            FROM conversations
            WHERE chat_id = ? AND sender = ? AND message_text = ?
            LIMIT 1
            """,
            (chat_id, normalized_sender, text),
        ).fetchone()
    return row is not None


def get_chat_history(chat_id: str, limit: int = 15) -> list[dict[str, Any]]:
    if limit < 0:
        raise ValueError("limit must be zero or greater")
    limit = min(limit, 15)
    with closing(_connect()) as connection:
        rows = connection.execute(
            """
            SELECT id, chat_id, sender, message_text, timestamp, scam_stage,
                   pressure_level
            FROM (
                SELECT id, chat_id, sender, message_text, timestamp, scam_stage,
                       pressure_level
                FROM conversations
                WHERE chat_id = ?
                ORDER BY timestamp DESC, id DESC
                LIMIT ?
            )
            ORDER BY timestamp ASC, id ASC
            """,
            (chat_id, limit),
        ).fetchall()

    keys = (
        "id",
        "chat_id",
        "sender",
        "message_text",
        "timestamp",
        "scam_stage",
        "pressure_level",
    )
    results = [dict(zip(keys, row)) for row in rows]
    for result in results:
        result["timestamp"] = display_timestamp(result["timestamp"])
    return results


def get_research_conversation(chat_id: str) -> dict[str, Any]:
    with closing(_connect()) as connection:
        message_rows = connection.execute(
            """
            SELECT
                sender, message_text, timestamp, scam_stage, pressure_level,
                delay_strategy, notes, extracted_artifacts, scam_score,
                detected_flags
            FROM conversations
            WHERE chat_id = ?
            ORDER BY id
            """,
            (chat_id,),
        ).fetchall()
        persona_row = connection.execute(
            "SELECT persona_id FROM chat_personas WHERE chat_id = ?",
            (chat_id,),
        ).fetchone()
        artifact_rows = connection.execute(
            """
            SELECT id, artifact_type, artifact_value, extracted_at
            FROM scam_artifacts
            WHERE chat_id = ?
            ORDER BY extracted_at, id
            """,
            (chat_id,),
        ).fetchall()
        settings_row = connection.execute(
            """
            SELECT is_auto_reply, manual_mode
            FROM chat_settings
            WHERE chat_id = ?
            """,
            (chat_id,),
        ).fetchone()
        pending_rows = connection.execute(
            """
            SELECT id, response_text, scam_stage, pressure_level, created_at
            FROM pending_replies
            WHERE chat_id = ? AND status = 'pending'
            ORDER BY id
            """,
            (chat_id,),
        ).fetchall()

    messages = []
    for (
        sender,
        text,
        timestamp,
        stage,
        pressure,
        delay_strategy,
        notes,
        extracted_artifacts,
        scam_score,
        detected_flags,
    ) in message_rows:
        telemetry = None
        if sender == "bot" and (stage is not None or pressure is not None):
            decoded_artifacts = json.loads(extracted_artifacts or "[]")
            telemetry = {
                "scam_stage": stage,
                "pressure_level": pressure,
                "delay_strategy": delay_strategy,
                "notes": notes,
                "extracted_artifacts": decoded_artifacts,
            }
        messages.append(
            {
                "role": "user" if sender == "scammer" else "assistant",
                "content": text,
                "created_at": display_timestamp(timestamp),
                "telemetry": telemetry,
                "scam_score": scam_score,
                "is_scam": (
                    scam_score is not None
                    and scam_score >= SCAM_REVIEW_THRESHOLD
                ),
                "detected_flags": json.loads(detected_flags or "[]"),
            }
        )

    # A CSV can be uploaded more than once. Keep the research view readable
    # even if older versions of the intake endpoint already stored duplicates.
    unique_messages = []
    seen_inbound: set[tuple[str, str]] = set()
    for message in messages:
        if message["role"] == "user":
            key = (message["role"], message["content"])
            if key in seen_inbound:
                continue
            seen_inbound.add(key)
        unique_messages.append(message)

    unique_artifacts = []
    seen_artifacts: set[tuple[str, str]] = set()
    for artifact_id, artifact_type, artifact_value, extracted_at in artifact_rows:
        artifact_key = (artifact_type, artifact_value)
        if artifact_key in seen_artifacts:
            continue
        seen_artifacts.add(artifact_key)
        unique_artifacts.append(
            {
                "id": artifact_id,
                "artifact_type": artifact_type,
                "artifact_value": artifact_value,
                "extracted_at": display_timestamp(extracted_at),
            }
        )

    return {
        "sender_id": chat_id,
        "persona_id": persona_row[0] if persona_row else None,
        "is_auto_reply": True if settings_row is None else bool(settings_row[0]),
        "manual_mode": False if settings_row is None else bool(settings_row[1]),
        "messages": unique_messages,
        "pending_replies": [
            {
                "id": reply_id,
                "response_text": response_text,
                "scam_stage": stage,
                "pressure_level": pressure,
                "created_at": display_timestamp(created_at),
            }
            for reply_id, response_text, stage, pressure, created_at in pending_rows
        ],
        "artifacts": unique_artifacts,
    }


def save_artifacts(chat_id: str, artifacts_list: list[Any]) -> None:
    rows: list[tuple[str, str, str]] = []
    for artifact in artifacts_list:
        if isinstance(artifact, Mapping):
            artifact_type = artifact.get("artifact_type", artifact.get("type"))
            artifact_value = artifact.get("artifact_value", artifact.get("value"))
        elif (
            isinstance(artifact, Sequence)
            and not isinstance(artifact, (str, bytes))
            and len(artifact) == 2
        ):
            artifact_type, artifact_value = artifact
        elif isinstance(artifact, str):
            artifact_type, artifact_value = "unknown", artifact
        else:
            raise ValueError(
                "Each artifact must be a string, a type/value pair, "
                "or a mapping with type and value"
            )

        if not isinstance(artifact_type, str) or not artifact_type.strip():
            raise ValueError("Artifact type must be a non-empty string")
        if not isinstance(artifact_value, str) or not artifact_value.strip():
            raise ValueError("Artifact value must be a non-empty string")
        rows.append((chat_id, artifact_type.strip(), artifact_value.strip()))

    with closing(_connect()) as connection:
        with connection:
            connection.executemany(
                """
                INSERT INTO scam_artifacts (chat_id, artifact_type, artifact_value)
                VALUES (?, ?, ?)
                """,
                rows,
            )


def _scam_category(scam_stage: str | None) -> str:
    stage = (scam_stage or "unknown").strip().lower().replace("-", "_").replace(" ", "_")
    if any(term in stage for term in ("romance", "relationship", "rapport", "groom", "friendship", "affection", "love", "trust")):
        return "Romance & relationship building"
    if any(term in stage for term in ("investment", "invest", "crypto", "trading", "trade", "return", "profit")):
        return "Investment & crypto"
    if any(term in stage for term in ("job", "task", "employment", "commission", "rating", "like-to-earn")):
        return "Job & task scams"
    if any(term in stage for term in ("impersonat", "government", "police", "agency", "authority", "bank officer")):
        return "Authority impersonation"
    if any(term in stage for term in ("delivery", "parcel", "customs", "courier", "advance_fee", "prize", "lottery", "giveaway", "claim")):
        return "Delivery, prize & advance-fee scams"
    if any(term in stage for term in ("mule", "money mule", "receive funds", "transfer funds")):
        return "Mule-account recruitment"
    if any(term in stage for term in ("account", "credential", "verification", "identity", "password", "otp", "phishing", "code")):
        return "Account & identity theft"
    if any(term in stage for term in ("payment", "pay", "transfer", "fee", "money", "loan", "gift", "bank")):
        return "Money & payment requests"
    return "Other / unclear"


def get_research_analytics() -> dict[str, Any]:
    with closing(_connect()) as connection:
        activity_cutoff = (
            "CURRENT_TIMESTAMP - INTERVAL '30 days'"
            if is_postgres(connection)
            else "datetime('now', '-30 days')"
        )
        engagement_duration = (
            "GREATEST(0, EXTRACT(EPOCH FROM "
            "(active_chats.last_activity - active_chats.first_activity)))"
            if is_postgres(connection)
            else "MAX(0, (julianday(active_chats.last_activity) "
            "- julianday(active_chats.first_activity)) * 86400)"
        )
        stage_rows = connection.execute(
            f"""
            WITH latest_stage AS (
                SELECT chat_id, scam_stage
                FROM (
                    SELECT
                        chat_id,
                        scam_stage,
                        ROW_NUMBER() OVER (
                            PARTITION BY chat_id
                            ORDER BY id DESC
                        ) AS row_number
                    FROM conversations
                    WHERE sender = 'bot' AND scam_stage IS NOT NULL
                )
                WHERE row_number = 1
            ),
            active_chats AS (
                SELECT chat_id, MAX(timestamp) AS last_activity
                FROM conversations
                GROUP BY chat_id
                HAVING MAX(timestamp) >= {activity_cutoff}
            )
            SELECT COALESCE(latest_stage.scam_stage, 'unknown'), COUNT(*)
            FROM active_chats
            LEFT JOIN latest_stage USING (chat_id)
            GROUP BY COALESCE(latest_stage.scam_stage, 'unknown')
            ORDER BY COUNT(*) DESC, 1
            """
        ).fetchall()
        aggregate_row = connection.execute(
            f"""
            WITH active_chats AS (
                SELECT
                    chat_id,
                    MIN(timestamp) AS first_activity,
                    MAX(timestamp) AS last_activity
                FROM conversations
                GROUP BY chat_id
                HAVING MAX(timestamp) >= {activity_cutoff}
            )
            SELECT
                COUNT(DISTINCT active_chats.chat_id),
                AVG(CASE WHEN conversations.sender = 'bot'
                         THEN conversations.pressure_level END),
                COUNT(conversations.id)
            FROM active_chats
            JOIN conversations USING (chat_id)
            """
        ).fetchone()
        engagement_rows = connection.execute(
            f"""
            WITH active_chats AS (
                SELECT
                    chat_id,
                    MIN(timestamp) AS first_activity,
                    MAX(timestamp) AS last_activity
                FROM conversations
                GROUP BY chat_id
                HAVING MAX(timestamp) >= {activity_cutoff}
            ),
            engagement AS (
                SELECT
                    COALESCE(chat_personas.persona_id, 'unassigned') AS persona_id,
                    active_chats.chat_id,
                    {engagement_duration} AS duration_seconds
                FROM active_chats
                LEFT JOIN chat_personas USING (chat_id)
            )
            SELECT
                persona_id,
                COUNT(*),
                SUM(duration_seconds),
                AVG(duration_seconds)
            FROM engagement
            GROUP BY persona_id
            ORDER BY persona_id
            """
        ).fetchall()
        category_rows = connection.execute(
            f"""
            WITH active_chats AS (
                SELECT chat_id
                FROM conversations
                GROUP BY chat_id
                HAVING MAX(timestamp) >= {activity_cutoff}
            ),
            latest_stage AS (
                SELECT chat_id, scam_stage
                FROM (
                    SELECT
                        chat_id,
                        scam_stage,
                        ROW_NUMBER() OVER (
                            PARTITION BY chat_id
                            ORDER BY id DESC
                        ) AS row_number
                    FROM conversations
                    WHERE sender = 'bot' AND scam_stage IS NOT NULL
                )
                WHERE row_number = 1
            )
            SELECT
                active_chats.chat_id,
                latest_stage.scam_stage,
                conversations.pressure_level
            FROM active_chats
            LEFT JOIN latest_stage USING (chat_id)
            LEFT JOIN conversations
                ON conversations.chat_id = active_chats.chat_id
                AND conversations.sender = 'bot'
            """
        ).fetchall()
        activity_rows = connection.execute(
            f"""
            SELECT DATE(timestamp) AS activity_date,
                   COUNT(*) AS incoming_messages,
                   SUM(CASE WHEN sender = 'scammer' AND scam_score >= ? THEN 1 ELSE 0 END)
            FROM conversations
            WHERE timestamp >= {activity_cutoff}
            GROUP BY DATE(timestamp)
            ORDER BY DATE(timestamp)
            """,
            (SCAM_REVIEW_THRESHOLD,),
        ).fetchall()

    active_count, average_pressure, total_messages = aggregate_row or (0, None, 0)
    category_metrics: dict[str, dict[str, Any]] = {}
    for chat_id, scam_stage, pressure in category_rows:
        category = _scam_category(scam_stage)
        metrics = category_metrics.setdefault(
            category,
            {"chat_ids": set(), "pressure_total": 0, "pressure_count": 0},
        )
        metrics["chat_ids"].add(chat_id)
        if pressure is not None:
            metrics["pressure_total"] += pressure
            metrics["pressure_count"] += 1

    category_order = (
        "Romance & relationship building",
        "Investment & crypto",
        "Job & task scams",
        "Authority impersonation",
        "Delivery, prize & advance-fee scams",
        "Mule-account recruitment",
        "Money & payment requests",
        "Account & identity theft",
        "Other / unclear",
    )
    category_summary = [
        {
            "category": category,
            "chat_count": len(category_metrics[category]["chat_ids"]),
            "mean_assessed_pressure": (
                round(
                    category_metrics[category]["pressure_total"]
                    / category_metrics[category]["pressure_count"],
                    2,
                )
                if category_metrics[category]["pressure_count"]
                else None
            ),
            "pressure_assessment_count": category_metrics[category]["pressure_count"],
        }
        for category in category_order
        if category in category_metrics
    ]
    return {
        "active_chats": active_count,
        "active_chats_by_scam_stage": [
            {"scam_stage": stage, "chat_count": count}
            for stage, count in stage_rows
        ],
        "average_pressure_level": average_pressure,
        "total_messages_exchanged": total_messages,
        "persona_engagement_duration": [
            {
                "persona_id": persona_id,
                "chat_count": chat_count,
                "total_duration_seconds": round(total_seconds or 0, 2),
                "average_duration_seconds": round(average_seconds or 0, 2),
            }
            for persona_id, chat_count, total_seconds, average_seconds in engagement_rows
        ],
        "scam_categories": category_summary,
        "activity_series": [
            {
                "date": str(activity_date),
                "incoming_messages": int(incoming_messages or 0),
                "detected_scams": int(detected_scams or 0),
            }
            for activity_date, incoming_messages, detected_scams in activity_rows
        ],
        "active_window_days": 30,
    }


def get_artifacts_for_export() -> list[dict[str, Any]]:
    with closing(_connect()) as connection:
        rows = connection.execute(
            """
            SELECT id, chat_id, artifact_type, artifact_value, extracted_at
            FROM scam_artifacts
            ORDER BY extracted_at, id
            """
        ).fetchall()

    keys = ("id", "chat_id", "artifact_type", "artifact_value", "extracted_at")
    results = [dict(zip(keys, row)) for row in rows]
    for result in results:
        result["extracted_at"] = display_timestamp(result["extracted_at"])
    return results


def get_threat_artifacts_for_export() -> list[dict[str, Any]]:
    """Return artifacts with the latest non-empty scam stage for each thread."""
    with closing(_connect()) as connection:
        rows = connection.execute(
            """
            SELECT
                artifact.id,
                artifact.artifact_type,
                artifact.artifact_value,
                artifact.extracted_at,
                conversation.scam_stage
            FROM scam_artifacts AS artifact
            LEFT JOIN conversations AS conversation
                ON conversation.id = (
                    SELECT latest.id
                    FROM conversations AS latest
                    WHERE latest.chat_id = artifact.chat_id
                        AND latest.scam_stage IS NOT NULL
                        AND TRIM(latest.scam_stage) != ''
                    ORDER BY latest.id DESC
                    LIMIT 1
                )
            ORDER BY artifact.extracted_at, artifact.id
            """
        ).fetchall()

    keys = (
        "id",
        "artifact_type",
        "artifact_value",
        "extracted_at",
        "scam_stage",
    )
    results = [dict(zip(keys, row)) for row in rows]
    for result in results:
        result["extracted_at"] = display_timestamp(result["extracted_at"])
    return results


def initialize_database() -> None:
    init_db()


def get_conversation(conversation_id: str) -> list[dict[str, str]]:
    with closing(_connect()) as connection:
        rows = connection.execute(
            """
            SELECT role, content
            FROM chat_history
            WHERE conversation_id = ?
            ORDER BY id
            """,
            (conversation_id,),
        ).fetchall()
    return [{"role": role, "content": content} for role, content in rows]


def log_event(
    level: str,
    message: str,
    conversation_id: str | None = None,
) -> None:
    with closing(_connect()) as connection:
        with connection:
            connection.execute(
                """
                INSERT INTO application_logs (level, message, conversation_id)
                VALUES (?, ?, ?)
                """,
                (level, message, conversation_id),
            )
