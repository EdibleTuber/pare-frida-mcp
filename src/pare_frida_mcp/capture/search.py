from __future__ import annotations

from typing import Any

from pare_frida_mcp.bounding import bound_text, fit_items
from pare_frida_mcp.capture.store import CaptureStore

_ALLOWED_FIELDS = {"hook", "url", "method", "cls", "ret", "source", "type"}
_ROW_RESERVE = 1024  # headroom for fit_items' reserve, the row's other fields,
                     # and the _ok envelope, so a single clipped row stays valid.


def _spread(seqs: list[int], limit: int) -> list[int]:
    """Pick `limit` seqs evenly spaced across the ordered list (inclusive of
    first and last). Deterministic. Assumes len(seqs) > limit and limit >= 1."""
    if limit <= 1:
        return seqs[:1]
    n = len(seqs)
    return [seqs[round(i * (n - 1) / (limit - 1))] for i in range(limit)]


def _lean(row: dict, byte_budget: int) -> tuple[dict, bool]:
    """Drop null/empty columns; clip oversized payload/summary string values so
    an oversized field can't by itself dominate the budget (fit_items still
    guarantees >=1 valid row). Returns (lean_row, clipped)."""
    clip_budget = max(0, byte_budget - _ROW_RESERVE)
    out: dict[str, Any] = {}
    clipped = False
    for k, v in row.items():
        if v in (None, ""):
            continue
        if k in ("payload", "summary") and isinstance(v, str):
            v, was = bound_text(v, clip_budget)
            clipped = clipped or was
        out[k] = v
    return out, clipped


def _fetch_rows(conn, seqs: list[int]) -> list[dict]:
    if not seqs:
        return []
    placeholders = ",".join("?" * len(seqs))
    rows = conn.execute(
        f"SELECT * FROM messages WHERE seq IN ({placeholders}) ORDER BY seq", seqs
    ).fetchall()
    return [dict(r) for r in rows]


def search_capture(store: CaptureStore, *, field: str | None = None,
                   contains: str | None = None, text: str | None = None,
                   limit: int = 50, byte_budget: int = 4096,
                   count_only: bool = False) -> dict[str, Any]:
    conn = store._conn  # internal access within the package
    if text is not None:
        count_sql = "SELECT count(*) AS c FROM messages_fts WHERE messages_fts MATCH ?"
        ids_sql = ("SELECT m.seq FROM messages m JOIN messages_fts f ON m.seq=f.rowid "
                   "WHERE messages_fts MATCH ? ORDER BY m.seq")
        params: tuple = (text,)
    elif field is not None and contains is not None:
        if field not in _ALLOWED_FIELDS:
            raise ValueError(f"field not searchable: {field!r}")
        like = f"%{contains}%"
        count_sql = f"SELECT count(*) AS c FROM messages WHERE {field} LIKE ?"
        ids_sql = f"SELECT seq FROM messages WHERE {field} LIKE ? ORDER BY seq"
        params = (like,)
    else:
        raise ValueError("provide either text=, or field= + contains=")

    total = conn.execute(count_sql, params).fetchone()["c"]
    if count_only:
        return {"total": total}

    seqs = [r["seq"] for r in conn.execute(ids_sql, params).fetchall()]
    sampled = total > limit
    chosen = _spread(seqs, limit) if sampled else seqs
    leaned = [_lean(r, byte_budget) for r in _fetch_rows(conn, chosen)]
    rows = [lr for lr, _ in leaned]
    fitted, _ = fit_items(rows, byte_budget)
    returned = len(fitted)
    clipped_any = any(leaned[i][1] for i in range(returned))
    return {"total": total, "returned": returned,
            "truncated": (returned < total) or clipped_any,
            "sampled": sampled, "matches": fitted}
