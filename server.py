from __future__ import annotations

import base64
import binascii
from datetime import datetime, timedelta, timezone
import os
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError
from argon2.low_level import Type
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from fastapi import FastAPI, Header, HTTPException
import psycopg
from psycopg import sql
from psycopg.rows import dict_row
from pydantic import BaseModel, Field


def database_url() -> str:
    url = os.getenv("DATABASE_URL", "").strip()
    if not url:
        raise RuntimeError("DATABASE_URL is required.")
    if url.startswith("postgres://"):
        return "postgresql://" + url.removeprefix("postgres://")
    return url


app = FastAPI(title=os.getenv("APP_NAME", "E2EE Messaging Relay"))
DATABASE_URL = database_url()
MESSAGE_TTL = timedelta(hours=int(os.getenv("MESSAGE_RETENTION_HOURS", "24")))
ARGON2 = PasswordHasher(
    time_cost=int(os.getenv("ARGON2_TIME_COST", "3")),
    memory_cost=int(os.getenv("ARGON2_MEMORY_COST", "65536")),
    parallelism=int(os.getenv("ARGON2_PARALLELISM", "4")),
    hash_len=32,
    salt_len=16,
    type=Type.ID,
)


class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=1)
    public_key: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)


class SendRequest(BaseModel):
    message_id: str = Field(..., min_length=1)
    sender: str = Field(..., min_length=1)
    recipient: str = Field(..., min_length=1)
    content: str = Field(..., min_length=1)
    chain_index: int = Field(..., ge=0)


def conn() -> psycopg.Connection:
    return psycopg.connect(DATABASE_URL, row_factory=dict_row)


get_connection = conn


def ensure_column(connection: psycopg.Connection, table: str, column: str, definition: str) -> None:
    exists = connection.execute(
        """
        SELECT 1 FROM information_schema.columns
        WHERE table_schema = 'public' AND table_name = %s AND column_name = %s
        """,
        (table, column),
    ).fetchone()
    if not exists:
        connection.execute(
            sql.SQL("ALTER TABLE {} ADD COLUMN {} {}").format(
                sql.Identifier(table), sql.Identifier(column), sql.SQL(definition)
            )
        )


def init_db() -> None:
    with conn() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                public_key TEXT NOT NULL,
                password_hash TEXT NOT NULL DEFAULT ''
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                sender TEXT NOT NULL REFERENCES users(username),
                recipient TEXT NOT NULL REFERENCES users(username),
                content TEXT NOT NULL,
                queued_at TIMESTAMPTZ NOT NULL,
                viewed_at TIMESTAMPTZ,
                expires_at TIMESTAMPTZ,
                chain_index INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        ensure_column(connection, "users", "password_hash", "TEXT NOT NULL DEFAULT ''")
        ensure_column(connection, "messages", "viewed_at", "TIMESTAMPTZ")
        ensure_column(connection, "messages", "expires_at", "TIMESTAMPTZ")
        ensure_column(connection, "messages", "chain_index", "INTEGER NOT NULL DEFAULT 0")
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_messages_recipient ON messages (recipient, queued_at)"
        )
        connection.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_messages_expires_at
            ON messages (expires_at) WHERE expires_at IS NOT NULL
            """
        )


init_db()


def clean(value: str, label: str) -> str:
    value = value.strip()
    if not value:
        raise HTTPException(status_code=400, detail=f"{label} cannot be blank.")
    return value


def normalize_public_key(public_key: str) -> str:
    try:
        raw = base64.b64decode(clean(public_key, "Public key"), validate=True)
        X25519PublicKey.from_public_bytes(raw)
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(
            status_code=400,
            detail="Public key must be a valid Base64-encoded X25519 public key.",
        ) from exc
    return base64.b64encode(raw).decode("ascii")


def verify_password(password_hash: str, password: str) -> None:
    try:
        ARGON2.verify(password_hash, password)
    except VerifyMismatchError as exc:
        raise HTTPException(status_code=401, detail="401 Unauthorized: invalid password.") from exc
    except VerificationError as exc:
        raise HTTPException(status_code=500, detail="Stored password hash is invalid.") from exc


def authenticate(
    connection: psycopg.Connection,
    username: str | None,
    password: str | None,
) -> str:
    username = clean(username or "", "X-Auth-Username")
    if not password:
        raise HTTPException(status_code=401, detail="401 Unauthorized: X-Auth-Password required.")
    row = connection.execute(
        "SELECT password_hash FROM users WHERE username = %s",
        (username,),
    ).fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="401 Unauthorized: invalid credentials.")
    verify_password(row["password_hash"], password)
    return username


def cleanup_expired(connection: psycopg.Connection) -> None:
    connection.execute(
        "DELETE FROM messages WHERE expires_at IS NOT NULL AND expires_at <= %s",
        (datetime.now(timezone.utc),),
    )


@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/register")
def register_user(request: RegisterRequest) -> dict[str, Any]:
    username = clean(request.username, "Username")
    public_key = normalize_public_key(request.public_key)
    password = clean(request.password, "Password")
    with conn() as connection:
        existing = connection.execute(
            "SELECT public_key, password_hash FROM users WHERE username = %s",
            (username,),
        ).fetchone()
        if not existing:
            connection.execute(
                "INSERT INTO users (username, public_key, password_hash) VALUES (%s, %s, %s)",
                (username, public_key, ARGON2.hash(password)),
            )
            already_registered = False
        else:
            if existing["public_key"] != public_key:
                raise HTTPException(
                    status_code=409,
                    detail="Username already has a different public key.",
                )
            verify_password(existing["password_hash"], password)
            already_registered = True
    return {
        "username": username,
        "public_key": public_key,
        "already_registered": already_registered,
    }


@app.get("/public-key/{username}")
def get_public_key(
    username: str,
    x_auth_username: str | None = Header(default=None, alias="X-Auth-Username"),
    x_auth_password: str | None = Header(default=None, alias="X-Auth-Password"),
) -> dict[str, str]:
    username = clean(username, "Username")
    with conn() as connection:
        authenticate(connection, x_auth_username, x_auth_password)
        row = connection.execute(
            "SELECT public_key FROM users WHERE username = %s",
            (username,),
        ).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail=f"User '{username}' is not registered.")
    return {"username": username, "public_key": row["public_key"]}


@app.post("/send")
def send_message(
    request: SendRequest,
    x_auth_username: str | None = Header(default=None, alias="X-Auth-Username"),
    x_auth_password: str | None = Header(default=None, alias="X-Auth-Password"),
) -> dict[str, str]:
    sender = clean(request.sender, "Sender")
    recipient = clean(request.recipient, "Recipient")
    message_id = clean(request.message_id, "Message ID")
    content = clean(request.content, "Content")
    with conn() as connection:
        cleanup_expired(connection)
        if authenticate(connection, x_auth_username, x_auth_password) != sender:
            raise HTTPException(status_code=403, detail="Authenticated user does not match sender.")
        if not connection.execute(
            "SELECT 1 FROM users WHERE username = %s",
            (recipient,),
        ).fetchone():
            raise HTTPException(status_code=404, detail=f"User '{recipient}' is not registered.")
        connection.execute(
            """
            INSERT INTO messages (id, sender, recipient, content, queued_at, chain_index)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (
                message_id,
                sender,
                recipient,
                content,
                datetime.now(timezone.utc),
                request.chain_index,
            ),
        )
    return {"status": "queued", "message_id": message_id, "recipient": recipient}


@app.get("/messages/{username}")
def get_messages(
    username: str,
    x_auth_username: str | None = Header(default=None, alias="X-Auth-Username"),
    x_auth_password: str | None = Header(default=None, alias="X-Auth-Password"),
) -> dict[str, Any]:
    username = clean(username, "Username")
    with conn() as connection:
        cleanup_expired(connection)
        if authenticate(connection, x_auth_username, x_auth_password) != username:
            raise HTTPException(status_code=403, detail="Authenticated user does not match inbox.")
        viewed_at = datetime.now(timezone.utc)
        expires_at = viewed_at + MESSAGE_TTL
        rows = connection.execute(
            """
            WITH claimed AS (
                SELECT id FROM messages
                WHERE recipient = %s AND viewed_at IS NULL
                ORDER BY queued_at, id
                FOR UPDATE SKIP LOCKED
            ),
            updated AS (
                UPDATE messages AS m
                SET viewed_at = %s, expires_at = %s
                FROM claimed
                WHERE m.id = claimed.id
                RETURNING
                    m.id, m.sender, m.recipient, m.content, m.queued_at,
                    m.viewed_at, m.expires_at, m.chain_index
            )
            SELECT id, sender, recipient, content, queued_at, viewed_at, expires_at, chain_index
            FROM updated
            ORDER BY queued_at, id
            """,
            (username, viewed_at, expires_at),
        ).fetchall()
    return {"username": username, "messages": rows, "count": len(rows)}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "server:app",
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "8000")),
    )
