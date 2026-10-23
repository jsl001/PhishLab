import json
import os
import sqlite3
from contextlib import closing
from pathlib import Path


_DEFAULT_DATABASE_PATH = Path(__file__).with_name("honeypot.db")
DATABASE_PATH = Path(
    os.getenv("MESSAGE_DATABASE_PATH", str(_DEFAULT_DATABASE_PATH))
)


def initialize_database() -> None:
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(DATABASE_PATH)) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        with connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sender_id TEXT NOT NULL,
                    direction TEXT NOT NULL
                        CHECK (direction IN ('incoming', 'reply')),
                    message_text TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_messages_sender
                ON messages (sender_id, id)
                """
            )
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS telemetry_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    message_id INTEGER NOT NULL
                        REFERENCES messages (id) ON DELETE CASCADE,
                    sender_id TEXT NOT NULL,
                    scam_stage TEXT NOT NULL,
                    pressure_level TEXT NOT NULL,
                    extracted_artifacts TEXT NOT NULL,
                    delay_strategy TEXT NOT NULL,
                    notes TEXT NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )


def save_message(sender_id: str, direction: str, message_text: str) -> int:
    if direction not in {"incoming", "reply"}:
        raise ValueError("direction must be 'incoming' or 'reply'")

    with closing(sqlite3.connect(DATABASE_PATH)) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        with connection:
            cursor = connection.execute(
                """
                INSERT INTO messages (sender_id, direction, message_text)
                VALUES (?, ?, ?)
                """,
                (sender_id, direction, message_text),
            )
    return cursor.lastrowid


def get_conversation_history(sender_id: str) -> list[dict[str, str]]:
    with closing(sqlite3.connect(DATABASE_PATH)) as connection:
        rows = connection.execute(
            """
            SELECT direction, message_text
            FROM messages
            WHERE sender_id = ?
            ORDER BY id
            """,
            (sender_id,),
        ).fetchall()

    return [
        {
            "role": "user" if direction == "incoming" else "assistant",
            "content": message_text,
        }
        for direction, message_text in rows
    ]


def get_conversation(sender_id: str) -> list[dict[str, object]]:
    with closing(sqlite3.connect(DATABASE_PATH)) as connection:
        rows = connection.execute(
            """
            SELECT
                messages.direction,
                messages.message_text,
                messages.created_at,
                telemetry_logs.scam_stage,
                telemetry_logs.pressure_level,
                telemetry_logs.extracted_artifacts,
                telemetry_logs.delay_strategy,
                telemetry_logs.notes
            FROM messages
            LEFT JOIN telemetry_logs ON telemetry_logs.message_id = messages.id
            WHERE messages.sender_id = ?
            ORDER BY messages.id
            """,
            (sender_id,),
        ).fetchall()

    conversation = []
    for direction, message_text, created_at, stage, pressure, artifacts, delay, notes in rows:
        telemetry = None
        if stage is not None:
            telemetry = {
                "scam_stage": stage,
                "pressure_level": pressure,
                "extracted_artifacts": json.loads(artifacts),
                "delay_strategy": delay,
                "notes": notes,
            }
        conversation.append(
            {
                "role": "user" if direction == "incoming" else "assistant",
                "content": message_text,
                "created_at": created_at,
                "telemetry": telemetry,
            }
        )
    return conversation


def save_telemetry(
    message_id: int,
    sender_id: str,
    scam_stage: str,
    pressure_level: str,
    extracted_artifacts: list[str],
    delay_strategy: str,
    notes: str,
) -> None:
    with closing(sqlite3.connect(DATABASE_PATH)) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        with connection:
            connection.execute(
                """
                INSERT INTO telemetry_logs (
                    message_id,
                    sender_id,
                    scam_stage,
                    pressure_level,
                    extracted_artifacts,
                    delay_strategy,
                    notes
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    message_id,
                    sender_id,
                    scam_stage,
                    pressure_level,
                    json.dumps(extracted_artifacts),
                    delay_strategy,
                    notes,
                ),
            )
