from __future__ import annotations

import json
from typing import Any

from pare_frida_mcp.bounding import bound_text
from pare_frida_mcp.capture.store import CaptureStore

_ALLOWED_FIELDS = {"hook", "url", "method", "cls", "ret", "source", "type"}


def search_capture(store: CaptureStore, *, field: str | None = None,
                   contains: str | None = None, text: str | None = None,
                   limit: int = 50, byte_budget: int = 4096) -> dict[str, Any]:
    conn = store._conn  # internal access within the package
    if text is not None:
        rows = conn.execute(
            "SELECT m.* FROM messages m JOIN messages_fts f ON m.seq=f.rowid "
            "WHERE messages_fts MATCH ? ORDER BY m.seq LIMIT ?",
            (text, limit),
        ).fetchall()
        total = conn.execute(
            "SELECT count(*) AS c FROM messages_fts WHERE messages_fts MATCH ?", (text,)
        ).fetchone()["c"]
    elif field is not None and contains is not None:
        if field not in _ALLOWED_FIELDS:
            raise ValueError(f"field not searchable: {field!r}")
        like = f"%{contains}%"
        rows = conn.execute(
            f"SELECT * FROM messages WHERE {field} LIKE ? ORDER BY seq LIMIT ?", (like, limit)
        ).fetchall()
        total = conn.execute(
            f"SELECT count(*) AS c FROM messages WHERE {field} LIKE ?", (like,)
        ).fetchone()["c"]
    else:
        raise ValueError("provide either text=, or field= + contains=")

    matches = [dict(r) for r in rows]
    blob, truncated = bound_text(json.dumps(matches), byte_budget)
    return {"total": total, "returned": len(matches), "truncated": truncated,
            "matches": json.loads(blob) if not truncated else matches[: max(1, len(matches) // 2)]}
