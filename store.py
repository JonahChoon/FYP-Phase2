"""
store.py -- SQLite tracker for the CTF Tutor web app.

Persists, per user:
  - progress  : hint level, solved flag, conversation id (per challenge)
  - messages  : the chat transcript (so conversations survive restarts)
  - events    : one row per action (chat / hint / flag) for the evaluation log
                (stores the REDACTED question/reply; flags are never stored)

Everything lives in one SQLite file (tracker.db). To move to another machine
(e.g. the Raspberry Pi), just copy that one file across -- no server, no export.
Set TRACKER_DB to change where it lives.
"""

import hashlib
import json
import os
import sqlite3
import time
import uuid
from contextlib import contextmanager

DB_PATH = os.environ.get("TRACKER_DB", os.path.join(os.path.dirname(__file__), "tracker.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS progress (
    user            TEXT NOT NULL,
    challenge       TEXT NOT NULL,
    hint_level      INTEGER NOT NULL DEFAULT 0,
    solved          INTEGER NOT NULL DEFAULT 0,
    conversation_id TEXT NOT NULL,
    updated_at      TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (user, challenge)
);
CREATE TABLE IF NOT EXISTS messages (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user       TEXT NOT NULL,
    challenge  TEXT NOT NULL,
    role       TEXT NOT NULL,           -- 'user' or 'tutor'
    content    TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_messages ON messages(user, challenge, id);
CREATE TABLE IF NOT EXISTS events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              REAL,
    event           TEXT,               -- 'chat' | 'hint_unlock' | 'flag_submit'
    user            TEXT,
    challenge       TEXT,
    prompt_version  TEXT,
    mode            TEXT,
    model           TEXT,
    hint_level      INTEGER,
    conversation_id TEXT,
    response_time   REAL,
    question        TEXT,               -- redacted
    reply           TEXT                -- redacted
);
"""


@contextmanager
def _conn():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    try:
        yield c
        c.commit()
    finally:
        c.close()


def init_db():
    with _conn() as c:
        c.executescript(SCHEMA)


# ---- progress -------------------------------------------------------------

def get_progress(user: str, challenge: str) -> dict:
    with _conn() as c:
        r = c.execute("SELECT * FROM progress WHERE user=? AND challenge=?",
                      (user, challenge)).fetchone()
        if r:
            return {"hint_level": r["hint_level"], "solved": bool(r["solved"]),
                    "conversation_id": r["conversation_id"]}
        cid = uuid.uuid4().hex
        c.execute("INSERT INTO progress(user, challenge, conversation_id) VALUES(?,?,?)",
                  (user, challenge, cid))
        return {"hint_level": 0, "solved": False, "conversation_id": cid}


def set_hint_level(user: str, challenge: str, level: int):
    get_progress(user, challenge)  # ensure row exists
    with _conn() as c:
        c.execute("UPDATE progress SET hint_level=?, updated_at=datetime('now') "
                  "WHERE user=? AND challenge=?", (level, user, challenge))


def set_solved(user: str, challenge: str):
    get_progress(user, challenge)
    with _conn() as c:
        c.execute("UPDATE progress SET solved=1, updated_at=datetime('now') "
                  "WHERE user=? AND challenge=?", (user, challenge))


def solved_map(user: str) -> dict:
    with _conn() as c:
        rows = c.execute("SELECT challenge, solved FROM progress WHERE user=?",
                         (user,)).fetchall()
    return {r["challenge"]: bool(r["solved"]) for r in rows}


# ---- messages -------------------------------------------------------------

def add_message(user: str, challenge: str, role: str, content: str):
    with _conn() as c:
        c.execute("INSERT INTO messages(user, challenge, role, content) VALUES(?,?,?,?)",
                  (user, challenge, role, content))


def get_messages(user: str, challenge: str) -> list:
    with _conn() as c:
        rows = c.execute("SELECT role, content FROM messages WHERE user=? AND challenge=? "
                         "ORDER BY id", (user, challenge)).fetchall()
    return [{"role": r["role"], "content": r["content"]} for r in rows]


def genai_history(user: str, challenge: str) -> list:
    """Stored transcript -> google-genai history format."""
    out = []
    for m in get_messages(user, challenge):
        out.append({"role": "user" if m["role"] == "user" else "model",
                    "parts": [{"text": m["content"]}]})
    return out


# ---- events (evaluation log) ---------------------------------------------

def reset_challenge(user: str, challenge: str):
    """Clear hints + chat for one challenge (fresh start). Events are kept as audit log."""
    with _conn() as c:
        c.execute("DELETE FROM messages WHERE user=? AND challenge=?", (user, challenge))
        c.execute("UPDATE progress SET hint_level=0, solved=0, conversation_id=?, "
                  "updated_at=datetime('now') WHERE user=? AND challenge=?",
                  (uuid.uuid4().hex, user, challenge))


def reset_user(user: str):
    """Clear ALL progress + chat for a user. Events are kept as audit log."""
    with _conn() as c:
        c.execute("DELETE FROM messages WHERE user=?", (user,))
        c.execute("DELETE FROM progress WHERE user=?", (user,))


def list_users() -> list:
    """Summary of every user who has activity (for the instructor dashboard)."""
    with _conn() as c:
        prog = c.execute("SELECT user, COUNT(*) chals, SUM(solved) solved, "
                         "MAX(updated_at) last FROM progress GROUP BY user").fetchall()
        msgs = c.execute("SELECT user, COUNT(*) n FROM messages GROUP BY user").fetchall()
    mmap = {r["user"]: r["n"] for r in msgs}
    return [{"user": r["user"], "solved": r["solved"] or 0, "attempted": r["chals"],
             "messages": mmap.get(r["user"], 0), "last": r["last"]} for r in prog]


def user_summary(user: str) -> list:
    """Per-challenge progress for one user."""
    with _conn() as c:
        rows = c.execute("SELECT challenge, hint_level, solved FROM progress WHERE user=?",
                         (user,)).fetchall()
        msgs = c.execute("SELECT challenge, COUNT(*) n FROM messages WHERE user=? "
                         "GROUP BY challenge", (user,)).fetchall()
    mmap = {r["challenge"]: r["n"] for r in msgs}
    return [{"challenge": r["challenge"], "hint_level": r["hint_level"],
             "solved": bool(r["solved"]), "messages": mmap.get(r["challenge"], 0)}
            for r in rows]


def log_event(**kw):
    with _conn() as c:
        c.execute(
            """INSERT INTO events(ts, event, user, challenge, prompt_version, mode,
                                  model, hint_level, conversation_id, response_time,
                                  question, reply)
               VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
            (time.time(), kw.get("event"), kw.get("user"), kw.get("challenge"),
             kw.get("prompt_version"), kw.get("mode"), kw.get("model"),
             kw.get("hint_level"), kw.get("conversation_id"), kw.get("response_time"),
             kw.get("question", ""), kw.get("reply", "")))