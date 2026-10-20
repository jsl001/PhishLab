import json
import os
import sqlite3
from collections.abc import Mapping, Sequence
from contextlib import closing
from pathlib import Path
from typing import Any

from backend.personas import DEFAULT_PERSONA_ID, get_persona


DATABASE_PATH = Path(
    os.getenv("DATABASE_PATH", str(Path(__file__).with_name("chat_history.db")))
)


def _connect() -> sqlite3.Connection:
    return sqlite3.connect(DATABASE_PATH)


def init_db() -> None:
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with closing(_connect()) as connection:
        with connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS conversations (
                    id INTEGER PRIMARY KEY,
                    chat_id TEXT NOT NULL,
                    sender TEXT NOT NULL CHECK (sender IN ('scammer', 'bot')),
                    message_text TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    scam_stage TEXT,
                    pressure_level INTEGER,
                    delay_strategy TEXT,
                    notes TEXT,
                    extracted_artifacts TEXT NOT NULL DEFAULT '[]'
                )
                """
            )
            conversation_columns = {
                row[1] for row in connection.execute("PRAGMA table_info(conversations)")
            }
            for column, definition in (
                ("delay_strategy", "TEXT"),
                ("notes", "TEXT"),
                ("extracted_artifacts", "TEXT NOT NULL DEFAULT '[]'"),
            ):
                if column not in conversation_columns:
                    connection.execute(
                        f"ALTER TABLE conversations ADD COLUMN {column} {definition}"
                    )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_conversations_chat_id
                ON conversations (chat_id, id)
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS scam_artifacts (
                    id INTEGER PRIMARY KEY,
                    chat_id TEXT NOT NULL,
                    artifact_type TEXT NOT NULL,
                    artifact_value TEXT NOT NULL,
                    extracted_at DATETIME DEFAULT CURRENT_TIMESTAMP
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
                        CHECK (is_auto_reply IN (0, 1))
                )
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS pending_replies (
                    id INTEGER PRIMARY KEY,
                    chat_id TEXT NOT NULL,
                    response_text TEXT NOT NULL,
                    scam_stage TEXT,
                    pressure_level INTEGER,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
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
                """
                CREATE TABLE IF NOT EXISTS chat_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    conversation_id TEXT NOT NULL,
                    role TEXT NOT NULL CHECK (role IN ('user', 'assistant')),
                    content TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
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
                """
                CREATE TABLE IF NOT EXISTS application_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    level TEXT NOT NULL,
                    message TEXT NOT NULL,
                    conversation_id TEXT,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
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
                """,
                (chat_id, response_text, stage, pressure),
            )
            pending_reply_id = cursor.lastrowid
    if pending_reply_id is None:
        raise RuntimeError("SQLite did not return an id for the pending reply")
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
    return [dict(zip(keys, row)) for row in rows]


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
                INSERT OR IGNORE INTO chat_personas (chat_id, persona_id)
                VALUES (?, ?)
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
) -> int:
    legacy_role = {"user": "user", "assistant": "assistant"}.get(sender)
    normalized_sender = {"user": "scammer", "assistant": "bot"}.get(sender, sender)
    if normalized_sender not in {"scammer", "bot"}:
        raise ValueError("sender must be 'scammer' or 'bot'")
    if pressure is not None and not isinstance(pressure, int):
        raise TypeError("pressure must be an integer or None")

    with closing(_connect()) as connection:
        with connection:
            cursor = connection.execute(
                """
                INSERT INTO conversations (
                    chat_id, sender, message_text, scam_stage, pressure_level,
                    delay_strategy, notes, extracted_artifacts
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
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
                ),
            )
            message_id = cursor.lastrowid
            if legacy_role is not None:
                connection.execute(
                    """
                    INSERT INTO chat_history (conversation_id, role, content)
                    VALUES (?, ?, ?)
                    """,
                    (chat_id, legacy_role, text),
                )
    if message_id is None:
        raise RuntimeError("SQLite did not return an id for the saved message")
    return message_id


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
    return [dict(zip(keys, row)) for row in rows]


def get_research_conversation(chat_id: str) -> dict[str, Any]:
    with closing(_connect()) as connection:
        message_rows = connection.execute(
            """
            SELECT
                sender, message_text, timestamp, scam_stage, pressure_level,
                delay_strategy, notes, extracted_artifacts
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
            "SELECT is_auto_reply FROM chat_settings WHERE chat_id = ?",
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
                "created_at": timestamp,
                "telemetry": telemetry,
            }
        )

    return {
        "sender_id": chat_id,
        "persona_id": persona_row[0] if persona_row else None,
        "is_auto_reply": True if settings_row is None else bool(settings_row[0]),
        "messages": messages,
        "pending_replies": [
            {
                "id": reply_id,
                "response_text": response_text,
                "scam_stage": stage,
                "pressure_level": pressure,
                "created_at": created_at,
            }
            for reply_id, response_text, stage, pressure, created_at in pending_rows
        ],
        "artifacts": [
            {
                "id": artifact_id,
                "artifact_type": artifact_type,
                "artifact_value": artifact_value,
                "extracted_at": extracted_at,
            }
            for artifact_id, artifact_type, artifact_value, extracted_at in artifact_rows
        ],
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
        stage_rows = connection.execute(
            """
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
                HAVING last_activity >= datetime('now', '-30 days')
            )
            SELECT COALESCE(latest_stage.scam_stage, 'unknown'), COUNT(*)
            FROM active_chats
            LEFT JOIN latest_stage USING (chat_id)
            GROUP BY COALESCE(latest_stage.scam_stage, 'unknown')
            ORDER BY COUNT(*) DESC, 1
            """
        ).fetchall()
        aggregate_row = connection.execute(
            """
            WITH active_chats AS (
                SELECT
                    chat_id,
                    MIN(timestamp) AS first_activity,
                    MAX(timestamp) AS last_activity
                FROM conversations
                GROUP BY chat_id
                HAVING last_activity >= datetime('now', '-30 days')
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
            """
            WITH active_chats AS (
                SELECT
                    chat_id,
                    MIN(timestamp) AS first_activity,
                    MAX(timestamp) AS last_activity
                FROM conversations
                GROUP BY chat_id
                HAVING last_activity >= datetime('now', '-30 days')
            ),
            engagement AS (
                SELECT
                    COALESCE(chat_personas.persona_id, 'unassigned') AS persona_id,
                    active_chats.chat_id,
                    MAX(
                        0,
                        (julianday(active_chats.last_activity)
                         - julianday(active_chats.first_activity)) * 86400
                    ) AS duration_seconds
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
            """
            WITH active_chats AS (
                SELECT chat_id
                FROM conversations
                GROUP BY chat_id
                HAVING MAX(timestamp) >= datetime('now', '-30 days')
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
    return [dict(zip(keys, row)) for row in rows]


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
