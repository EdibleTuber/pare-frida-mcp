from __future__ import annotations

import json
from typing import Any

from pare_frida_mcp.bounding import fit_items
from pare_frida_mcp.capture.store import CaptureStore

# Human-facing complete read. Own allowlist (NOT search.py's _ALLOWED_FIELDS):
# LIKE on `summary` is the deterministic name match; `payload` is excluded
# because it is serialized JSON (LIKE would match keys/punctuation).
_PAGE_FIELDS = {"source", "type", "summary"}


def _item(row: dict) -> dict:
    """The original snapshot item lives in the JSON `payload` column."""
    raw = row.get("payload")
    return json.loads(raw) if raw else {}


def page_rows(store: CaptureStore, *, source: str, field: str | None = None,
              contains: str | None = None, byte_budget: int = 262144) -> dict[str, Any]:
    """Complete (unsampled) read of one snapshot's rows, byte-honest.

    Returns {rows, total, shown}. `total` is the true row count; `shown` is how
    many whole rows fit byte_budget (fit_items). Never samples, never drops a
    partial row.
    """
    conn = store._conn  # internal access within the package
    if field is not None and contains is not None:
        if field not in _PAGE_FIELDS:
            raise ValueError(f"field not searchable: {field!r}")
        where = f"source = ? AND {field} LIKE ?"
        params: tuple = (source, f"%{contains}%")
    else:
        where = "source = ?"
        params = (source,)
    total = conn.execute(
        f"SELECT count(*) AS c FROM messages WHERE {where}", params).fetchone()["c"]
    rows = conn.execute(
        f"SELECT * FROM messages WHERE {where} ORDER BY seq", params).fetchall()
    items = [_item(dict(r)) for r in rows]
    fitted, _ = fit_items(items, byte_budget)
    return {"rows": fitted, "total": total, "shown": len(fitted)}


def list_sources(store: CaptureStore) -> list[dict]:
    """Catalog of distinct sources with row counts, ordered by source."""
    conn = store._conn
    rows = conn.execute(
        "SELECT source, count(*) AS c FROM messages GROUP BY source ORDER BY source"
    ).fetchall()
    return [{"source": r["source"], "count": r["c"]} for r in rows]
