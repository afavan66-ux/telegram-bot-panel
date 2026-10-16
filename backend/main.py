import os
import sqlite3
from pathlib import Path
from typing import Optional

import httpx
from cryptography.fernet import Fernet, InvalidToken
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

load_dotenv()

ADMIN_API_KEY = os.getenv("ADMIN_API_KEY", "")
FERNET_KEY = os.getenv("FERNET_KEY", "")
DATABASE_PATH = Path(os.getenv("DATABASE_PATH", "./data/bots.sqlite3"))

if not ADMIN_API_KEY or len(ADMIN_API_KEY) < 32:
    raise RuntimeError("Set ADMIN_API_KEY to a random secret of at least 32 characters.")
if not FERNET_KEY:
    raise RuntimeError("Set FERNET_KEY in your environment.")
try:
    cipher = Fernet(FERNET_KEY.encode())
except Exception as exc:
    raise RuntimeError("FERNET_KEY is invalid. Generate one with Fernet.generate_key().") from exc

app = FastAPI(title="Private Telegram Bot Manager", version="0.1.0")


def db():
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with db() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS bots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                display_name TEXT NOT NULL,
                telegram_id INTEGER NOT NULL UNIQUE,
                username TEXT NOT NULL,
                token_encrypted BLOB NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
        """)


init_db()


def require_admin(authorization: Optional[str] = Header(default=None)):
    # Starter protection for local/private testing only. Do not embed this key in an APK.
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Authentication required")
    supplied = authorization[7:]
    import hmac
    if not hmac.compare_digest(supplied, ADMIN_API_KEY):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return True


class BotCreate(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    token: str = Field(min_length=20, max_length=256)


@app.get("/health")
def health():
    return {"ok": True, "service": "telegram-bot-manager"}


@app.get("/api/bots", dependencies=[Depends(require_admin)])
def list_bots():
    with db() as conn:
        rows = conn.execute(
            "SELECT id, display_name, telegram_id, username, created_at FROM bots ORDER BY id DESC"
        ).fetchall()
    return {"bots": [dict(row) for row in rows]}


@app.post("/api/bots", dependencies=[Depends(require_admin)])
async def add_bot(payload: BotCreate):
    name = payload.name.strip()
    token = payload.token.strip()
    if not name:
        raise HTTPException(status_code=422, detail="Name cannot be empty")

    # Validate token with Telegram; never log or return it.
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(f"https://api.telegram.org/bot{token}/getMe")
        data = response.json()
    except Exception:
        raise HTTPException(status_code=502, detail="Could not contact Telegram API")
    if response.status_code != 200 or not data.get("ok"):
        raise HTTPException(status_code=422, detail="Telegram rejected this bot token")

    bot = data["result"]
    encrypted = cipher.encrypt(token.encode())
    try:
        with db() as conn:
            cur = conn.execute(
                "INSERT INTO bots(display_name, telegram_id, username, token_encrypted) VALUES(?,?,?,?)",
                (name, int(bot["id"]), bot.get("username") or "", encrypted),
            )
            bot_id = cur.lastrowid
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="This Telegram bot is already registered")

    return {"id": bot_id, "name": name, "telegram_id": bot["id"], "username": bot.get("username") or ""}


@app.delete("/api/bots/{bot_id}", dependencies=[Depends(require_admin)])
def remove_bot(bot_id: int):
    # Removes this panel's record only; it does not delete the Telegram bot account.
    with db() as conn:
        cur = conn.execute("DELETE FROM bots WHERE id = ?", (bot_id,))
    if cur.rowcount == 0:
        raise HTTPException(status_code=404, detail="Bot not found")
    return {"ok": True, "removed_from_panel": True}


@app.get("/api/bots/{bot_id}/token-check", dependencies=[Depends(require_admin)])
async def check_bot_token(bot_id: int):
    # Reports validity only. Never returns the token.
    with db() as conn:
        row = conn.execute("SELECT token_encrypted FROM bots WHERE id=?", (bot_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="Bot not found")
    try:
        token = cipher.decrypt(row["token_encrypted"]).decode()
    except InvalidToken:
        raise HTTPException(status_code=500, detail="Stored token could not be decrypted")
    async with httpx.AsyncClient(timeout=10) as client:
        response = await client.get(f"https://api.telegram.org/bot{token}/getMe")
    data = response.json()
    return {"valid": bool(response.status_code == 200 and data.get("ok"))}
