# Sessionless snapshot store

**Date:** 2026-05-31
**Status:** Approved design

## Problem & motivation

PARE is a sidekick for a human-driven testing loop, and the agent's scarcest
resource is context. The desired default is **persist-then-search**: a tool runs,
its full result lands in a store, the agent gets back a tiny summary + a handle,
and it then searches/reads only the slices it needs — instead of dumping large
results inline and burning context every turn.

This pattern already exists for the Frida hook *stream*: the per-session
`CaptureStore` (SQLite + FTS5) backs `search_capture`/`read_capture`. But that
store is **session-keyed** (created in `register_session`, addressed via
`MANAGER.get(session_id)`), and the next feature — device-scoped enumeration
tools (`enumerate_processes`/`enumerate_applications`) — has **no session**. This
spec builds the missing piece: a **sessionless snapshot store** those tools (and
any future device-scoped tool) can write into, reusing the existing search/read
surface.

This is foundational infrastructure. It adds **no new MCP tool**; it adds a store
plus handle-routing so the existing `search_capture`/`read_capture` can address
it. The enumeration tools are a separate follow-up that consumes this.

## Two data shapes (why this store is distinct)

- **Logs / streams** (hook events, `java_hook` captures, script messages):
  append semantics — history you want to keep and search. Served by the existing
  *session* store. **Unchanged by this work.**
- **Snapshots** (`list_devices`, `enumerate_processes`,
  `enumerate_applications`, …): a point-in-time view of current device state. You
  only ever want the latest; a stale process list is simply wrong. **Replace
  semantics.** This is what the snapshot store holds.

## Design

### Storage: one in-memory `CaptureStore`, process-lifetime, wiped on restart

The snapshot store is the *same* `CaptureStore` schema (SQLite + FTS5), opened
against `sqlite3.connect(":memory:")`, as a single instance living for the
worker's lifetime. Wipe-on-restart is free (memory dies with the process), there
is no disk footprint, and snapshots regenerate cheaply, so nothing of value is
lost on restart.

New constructor on `CaptureStore`:

```python
@classmethod
def open_memory(cls, blob_threshold: int = 1 << 30) -> "CaptureStore":
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.executescript(_SCHEMA)
    # No session_dir for an in-memory store; spill is disabled via a huge
    # blob_threshold because snapshot payloads ({"pid","name"}) are tiny.
    return cls(conn, session_dir=None, blob_threshold=blob_threshold)
```

`write()` only touches `self._dir` when `len(payload_json) > blob_threshold`;
with the huge default and tiny per-item payloads, that branch never runs, so
`session_dir=None` is safe. (The plan will add a guard/assert documenting that
in-memory stores must not spill.)

### Keying & replace: per `(tool, normalized args)`, upsert by delete-then-insert

Each enumeration result is written as **one row per item** (one row per process /
per app), every row tagged with the same `source` query-key, e.g.
`enumerate_applications:device=emulator-5554:filter=bank`. A stable key builder:

```python
def snapshot_key(tool: str, **args) -> str:
    parts = [tool] + [f"{k}={v}" for k, v in sorted(args.items()) if v not in ("", None)]
    return ":".join(parts)
```

"Re-run wipes old, pulls fresh" = upsert scoped to that key: delete the prior
rows for the key, insert the fresh rows. Distinct args ⇒ distinct key ⇒
coexisting snapshots (per-query behavior). New method on `CaptureStore`:

```python
def delete_by_source(self, source: str) -> int:
    rows = self._conn.execute(
        "SELECT seq FROM messages WHERE source=?", (source,)
    ).fetchall()
    for r in rows:
        # External-content FTS5 requires explicit delete-sync.
        self._conn.execute(
            "INSERT INTO messages_fts(messages_fts, rowid, summary, payload) "
            "VALUES ('delete', ?, '', '')", (r["seq"],)
        )
    self._conn.execute("DELETE FROM messages WHERE source=?", (source,))
    self._conn.commit()
    return len(rows)
```

(No blob cleanup needed: the in-memory store never spills. The plan notes this
method is only correct for the spill-disabled in-memory store.)

### The `SnapshotStore` wrapper (new module `core/snapshots.py`)

Owns the in-memory `CaptureStore`, enforces an LRU bound on the number of
distinct query-keys (so a marathon session can't grow unbounded), and exposes the
write API. The reserved handle constant lives here too.

```python
from collections import OrderedDict
from pare_frida_mcp.capture.store import CaptureStore

SNAPSHOT_HANDLE = "@snapshots"  # reserved; not a valid session id

class SnapshotStore:
    def __init__(self, max_keys: int = 32):
        self.store = CaptureStore.open_memory()
        self._keys: OrderedDict[str, None] = OrderedDict()
        self._max_keys = max_keys

    def replace(self, source: str, items: list[dict], summary_field: str = "name") -> int:
        self.store.delete_by_source(source)
        for item in items:
            self.store.write({
                "type": "snapshot", "source": source,
                "summary": str(item.get(summary_field, "")),
                "payload": item,
            })
        self._keys.pop(source, None)
        self._keys[source] = None          # most-recently-used
        while len(self._keys) > self._max_keys:
            old, _ = self._keys.popitem(last=False)
            self.store.delete_by_source(old)
        return len(items)
```

A single module-level instance is created in `tools.py` alongside `MANAGER`:
`SNAPSHOTS = SnapshotStore()`.

### Retrieval: route `search_capture` / `read_capture` to the snapshot store

`search.py`/`read.py` already take a `CaptureStore` and are session-agnostic — no
change there. Only the two **handlers** in `tools.py` change, to resolve the
store from the handle before the existing session path:

```python
def _resolve_store(handle: str):
    if handle == SNAPSHOT_HANDLE:         # reserved sessionless handle
        return SNAPSHOTS.store, None
    sid = validate_session_id(handle)
    s = MANAGER.get(sid)
    return s.store, s

async def search_capture(session_id, field="", contains="", text="", byte_budget=0):
    try:
        store, s = _resolve_store(session_id)
        if s is not None:
            s.flush()                      # only sessions have a pending queue
        budget = byte_budget or _CAP
        res = _search_capture(store, field=field or None, contains=contains or None,
                              text=text or None, byte_budget=budget)
        return _ok(f"{res['total']} matches", **res)
    except Exception as e:
        return _err("search_capture failed", e)
```

`read_capture` changes the same way (resolve store, skip `flush` when `s is
None`). The `session_id` input-schema description for both is updated to note that
the reserved handle `@snapshots` targets device-snapshot results.

Because each item is its own FTS-indexed row tagged by `source`, the agent can:
- `search_capture("@snapshots", field="source", contains="enumerate_applications")`
  to page a specific snapshot, or
- `search_capture("@snapshots", text="bank")` to find matching items across
  snapshots — byte-bounded, exactly the context-economy win.

`field="source"` is already in `search.py`'s `_ALLOWED_FIELDS`, so no change to
the search engine is required.

### How the future enumeration tools will use it (context only — not built here)

Each enumerate handler will: enumerate → `SNAPSHOTS.replace(snapshot_key(...),
items)` → return a *tiny* inline payload (summary + `total` + the `@snapshots`
handle + the `source` key), never the list itself. That feature is specced and
planned separately; `page_items` (already landed) will bound any "read the whole
snapshot, paged" responses.

## What changes

- `capture/store.py` — add `open_memory()` classmethod and `delete_by_source()`;
  make `session_dir` optional (`None`) for in-memory stores.
- `core/snapshots.py` — **new**: `SnapshotStore`, `snapshot_key()`,
  `SNAPSHOT_HANDLE`.
- `tools.py` — add `SNAPSHOTS = SnapshotStore()`; add `_resolve_store()`; route
  `search_capture`/`read_capture` through it; guard `flush()` for the sessionless
  case.
- `contract.py` — update the `session_id` descriptions of `search_capture` and
  `read_capture` to mention the `@snapshots` handle. No new tool, no tier change.

## Testing

- **Unit — store:** `open_memory()` yields a usable FTS-backed store; `write` +
  `delete_by_source` round-trip; `delete_by_source` removes both the row and its
  FTS entry (a later `text=` search no longer matches it).
- **Unit — SnapshotStore:** `replace(key, items)` then re-`replace(key, fresh)`
  leaves only the fresh rows for that key (replace semantics); a second distinct
  key coexists (per-query); exceeding `max_keys` evicts the least-recently-used
  key's rows (assert its rows are gone, the newest remain).
- **Unit — handler routing:** `search_capture("@snapshots", text=...)` and
  `read_capture("@snapshots", seq=...)` resolve to the snapshot store without a
  session (monkeypatch `SNAPSHOTS.replace(...)` some rows first); confirm no
  `flush`/`MANAGER` lookup occurs for the handle; confirm a normal `session_id`
  still routes to the session store unchanged.
- **Regression:** existing `search_capture`/`read_capture` session tests still
  pass (the handler change must not alter the session path).

## Out of scope

- Enumeration tools (`enumerate_processes`/`enumerate_applications`) — the
  consumer feature, specced/planned separately.
- Agent-authored artifacts (plans, findings, notes) — a distinct, larger feature.
- On-disk durability for snapshots — deliberately omitted (regenerate cheaply).
- Changing the session/stream store's append semantics.
