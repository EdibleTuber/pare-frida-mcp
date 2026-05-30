from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any

_SCHEMA = """
CREATE TABLE IF NOT EXISTS messages (
  seq INTEGER PRIMARY KEY,
  ts REAL NOT NULL,
  type TEXT NOT NULL,
  source TEXT,
  hook TEXT, url TEXT, method TEXT, cls TEXT, ret TEXT,
  summary TEXT, payload TEXT, blob_ref TEXT
);
CREATE INDEX IF NOT EXISTS idx_messages_ts ON messages(ts);
CREATE INDEX IF NOT EXISTS idx_messages_type ON messages(type);
CREATE INDEX IF NOT EXISTS idx_messages_source ON messages(source);
CREATE INDEX IF NOT EXISTS idx_messages_hook ON messages(hook);
CREATE INDEX IF NOT EXISTS idx_messages_url ON messages(url);
CREATE INDEX IF NOT EXISTS idx_messages_method ON messages(method);
CREATE INDEX IF NOT EXISTS idx_messages_cls ON messages(cls);
CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts
  USING fts5(summary, payload, content='messages', content_rowid='seq');
"""

_PROMOTE = {"hook": "hook", "url": "url", "method": "method", "class": "cls", "ret": "ret"}


class CaptureStore:
    def __init__(self, conn: sqlite3.Connection, session_dir: Path, blob_threshold: int):
        self._conn = conn
        self._dir = session_dir
        self._blob_threshold = blob_threshold

    @classmethod
    def open(cls, capture_dir: Path, session_id: str, blob_threshold: int) -> "CaptureStore":
        session_dir = Path(capture_dir) / session_id
        session_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        db_path = session_dir / "capture.db"
        conn = sqlite3.connect(db_path)
        db_path.chmod(0o600)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(_SCHEMA)
        return cls(conn, session_dir, blob_threshold)

    def write(self, message: dict[str, Any]) -> int:
        payload = message.get("payload", {})
        payload_json = json.dumps(payload)
        promoted = {col: (payload.get(key) if isinstance(payload, dict) else None)
                    for key, col in _PROMOTE.items()}
        spill = len(payload_json) > self._blob_threshold

        # INSERT first to get the authoritative seq from SQLite autoincrement,
        # then write the blob (if needed) using that seq so filename always matches.
        cur = self._conn.execute(
            "INSERT INTO messages (ts, type, source, hook, url, method, cls, ret, summary, payload, blob_ref)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (time.time(), message.get("type", "send"), message.get("source"),
             promoted["hook"], promoted["url"], promoted["method"], promoted["cls"],
             _short(promoted["ret"]), message.get("summary"), payload_json, None),
        )
        seq = cur.lastrowid

        blob_ref = None
        if spill:
            blobs = self._dir / "blobs"
            blobs.mkdir(exist_ok=True, mode=0o700)
            blob_path = blobs / f"{seq}.bin"
            try:
                blob_path.write_bytes(payload_json.encode("utf-8"))
                blob_path.chmod(0o600)
            except OSError:
                blob_path.unlink(missing_ok=True)
                raise
            blob_ref = str(blob_path)
            # Null the row's payload column once the spill succeeds — the full
            # JSON now lives in the blob file. Keeps the row small (the whole
            # point of spill); read_capture restores payload from blob_ref.
            # The FTS5 entry below still gets the full payload_json so search
            # works on spilled records.
            self._conn.execute(
                "UPDATE messages SET payload=NULL, blob_ref=? WHERE seq=?",
                (blob_ref, seq),
            )

        self._conn.execute(
            "INSERT INTO messages_fts (rowid, summary, payload) VALUES (?,?,?)",
            (seq, message.get("summary") or "", payload_json),
        )
        self._conn.commit()
        return seq

    def get(self, seq: int) -> dict[str, Any] | None:
        row = self._conn.execute("SELECT * FROM messages WHERE seq=?", (seq,)).fetchone()
        return dict(row) if row else None

    def close(self) -> None:
        self._conn.close()


def _short(value: Any, limit: int = 200) -> str | None:
    if value is None:
        return None
    s = str(value)
    return s if len(s) <= limit else s[:limit]
