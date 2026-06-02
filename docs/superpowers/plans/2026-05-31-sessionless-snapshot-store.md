# Sessionless Snapshot Store Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an in-memory, replace-on-rerun snapshot store that device-scoped tools can write into, addressable through the existing `search_capture`/`read_capture` tools via a reserved `@snapshots` handle.

**Architecture:** Reuse the existing `CaptureStore` (SQLite + FTS5) opened in-memory as a single process-lifetime instance. A thin `SnapshotStore` wrapper provides per-`(tool,args)` replace semantics (`delete_by_source` + insert, one FTS-indexed row per item) and an LRU bound on distinct query-keys. The two read-tool handlers gain handle-routing; the search/read engine is untouched because it already takes a `CaptureStore` object.

**Tech Stack:** Python 3, SQLite (stdlib `sqlite3`), FTS5, pytest / pytest-asyncio.

**Spec:** `docs/superpowers/specs/2026-05-31-sessionless-snapshot-store-design.md`

**Note on running tests in this environment:** the package is import-path-based; run pytest as `PYTHONPATH=src python3 -m pytest ...` if a bare invocation can't import `pare_frida_mcp`.

---

## File Structure

- `src/pare_frida_mcp/capture/store.py` — **modify**: add `open_memory()` classmethod and `delete_by_source()`; allow `session_dir=None`.
- `src/pare_frida_mcp/core/snapshots.py` — **create**: `SNAPSHOT_HANDLE`, `snapshot_key()`, `SnapshotStore`.
- `src/pare_frida_mcp/tools.py` — **modify**: add `SNAPSHOTS` instance, `_resolve_store()`, route `search_capture`/`read_capture`, guard `flush()`.
- `src/pare_frida_mcp/contract.py` — **modify**: mention `@snapshots` in the `search_capture`/`read_capture` `session_id` descriptions.
- `tests/unit/test_capture_store.py` — **modify**: tests for `open_memory` + `delete_by_source`.
- `tests/unit/test_snapshots.py` — **create**: tests for `SnapshotStore` + `snapshot_key`.
- `tests/unit/test_snapshot_routing.py` — **create**: tests for handler routing.

---

## Task 1: CaptureStore — in-memory constructor + source delete

**Files:**
- Modify: `src/pare_frida_mcp/capture/store.py`
- Test: `tests/unit/test_capture_store.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_capture_store.py` (keep the existing `import json` at the top; add the `search_capture` import there too):

```python
from pare_frida_mcp.capture.search import search_capture


def test_open_memory_is_usable_and_searchable():
    store = CaptureStore.open_memory()
    seq = store.write({"type": "snapshot", "source": "enum:dev=A",
                       "payload": {"pid": 1, "name": "initd"}, "summary": "initd"})
    assert seq == 1
    assert store.get(seq)["source"] == "enum:dev=A"
    # FTS works in-memory:
    res = search_capture(store, text="initd")
    assert res["total"] == 1
    store.close()


def test_delete_by_source_removes_rows_and_fts_entries():
    store = CaptureStore.open_memory()
    store.write({"type": "snapshot", "source": "enum:dev=A",
                 "payload": {"pid": 1, "name": "alpha"}, "summary": "alpha"})
    store.write({"type": "snapshot", "source": "enum:dev=A",
                 "payload": {"pid": 2, "name": "beta"}, "summary": "beta"})
    store.write({"type": "snapshot", "source": "enum:dev=B",
                 "payload": {"pid": 3, "name": "gamma"}, "summary": "gamma"})

    removed = store.delete_by_source("enum:dev=A")
    assert removed == 2

    # Rows for the source are gone...
    assert search_capture(store, field="source", contains="enum:dev=A")["total"] == 0
    # ...and the FTS index no longer matches them (guards the orphaned-index bug).
    assert search_capture(store, text="alpha")["total"] == 0
    assert search_capture(store, text="beta")["total"] == 0
    # The other source is untouched.
    assert search_capture(store, text="gamma")["total"] == 1
    store.close()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `PYTHONPATH=src python3 -m pytest tests/unit/test_capture_store.py -v`
Expected: FAIL — `AttributeError: type object 'CaptureStore' has no attribute 'open_memory'`.

- [ ] **Step 3: Implement `open_memory` and `delete_by_source`**

In `src/pare_frida_mcp/capture/store.py`, change `__init__` to accept an optional `session_dir` (the type hint becomes `Path | None`):

```python
    def __init__(self, conn: sqlite3.Connection, session_dir: Path | None, blob_threshold: int):
        self._conn = conn
        self._dir = session_dir
        self._blob_threshold = blob_threshold
```

Add these two methods to the `CaptureStore` class (place after the existing `open` classmethod and `get`/`close` methods respectively — anywhere in the class body is fine):

```python
    @classmethod
    def open_memory(cls, blob_threshold: int = 1 << 30) -> "CaptureStore":
        """In-memory store for sessionless snapshots. Wiped when the process
        exits. Spill is effectively disabled by the huge blob_threshold —
        snapshot payloads are tiny, so write() never touches a session_dir
        (which is None here)."""
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.executescript(_SCHEMA)
        return cls(conn, None, blob_threshold)

    def delete_by_source(self, source: str) -> int:
        """Delete all rows for a source key and re-sync the FTS index.

        messages_fts is an external-content FTS5 table; a 'delete' command
        would require re-supplying each row's original indexed values, and
        anything else orphans index entries (stale text= matches survive).
        Rebuilding re-syncs the whole index from the content table — foolproof,
        and cheap on an in-memory store capped at a few hundred rows. Correct
        only for the spill-disabled in-memory store (no blob files to clean up).
        """
        cur = self._conn.execute("DELETE FROM messages WHERE source=?", (source,))
        self._conn.execute("INSERT INTO messages_fts(messages_fts) VALUES ('rebuild')")
        self._conn.commit()
        return cur.rowcount
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `PYTHONPATH=src python3 -m pytest tests/unit/test_capture_store.py -v`
Expected: PASS (existing store tests + the two new ones).

- [ ] **Step 5: Commit**

```bash
git add src/pare_frida_mcp/capture/store.py tests/unit/test_capture_store.py
git commit -m "feat(store): in-memory CaptureStore + delete_by_source with FTS rebuild

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: SnapshotStore wrapper + key builder

**Files:**
- Create: `src/pare_frida_mcp/core/snapshots.py`
- Test: `tests/unit/test_snapshots.py` (create)

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_snapshots.py`:

```python
from pare_frida_mcp.core.snapshots import SnapshotStore, snapshot_key, SNAPSHOT_HANDLE
from pare_frida_mcp.capture.search import search_capture


def test_snapshot_key_is_stable_and_drops_empty_args():
    k = snapshot_key("enumerate_processes", device_id="emulator-5554", filter="")
    assert k == "enumerate_processes:device_id=emulator-5554"
    # order-independent
    assert snapshot_key("t", b="2", a="1") == snapshot_key("t", a="1", b="2")


def test_handle_constant():
    assert SNAPSHOT_HANDLE == "@snapshots"


def test_replace_is_upsert_per_key():
    snaps = SnapshotStore()
    key = "enumerate_processes:device_id=A"
    snaps.replace(key, [{"pid": 1, "name": "old1"}, {"pid": 2, "name": "old2"}])
    snaps.replace(key, [{"pid": 9, "name": "fresh"}])  # re-run replaces
    assert search_capture(snaps.store, field="source", contains=key)["total"] == 1
    assert search_capture(snaps.store, text="old1")["total"] == 0
    assert search_capture(snaps.store, text="fresh")["total"] == 1


def test_distinct_keys_coexist():
    snaps = SnapshotStore()
    snaps.replace("enumerate_processes:device_id=A", [{"pid": 1, "name": "aaa"}])
    snaps.replace("enumerate_processes:device_id=B", [{"pid": 1, "name": "bbb"}])
    assert search_capture(snaps.store, text="aaa")["total"] == 1
    assert search_capture(snaps.store, text="bbb")["total"] == 1


def test_lru_evicts_oldest_key():
    snaps = SnapshotStore(max_keys=2)
    snaps.replace("k1", [{"pid": 1, "name": "one"}])
    snaps.replace("k2", [{"pid": 2, "name": "two"}])
    snaps.replace("k3", [{"pid": 3, "name": "three"}])  # evicts k1
    assert search_capture(snaps.store, text="one")["total"] == 0
    assert search_capture(snaps.store, text="two")["total"] == 1
    assert search_capture(snaps.store, text="three")["total"] == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `PYTHONPATH=src python3 -m pytest tests/unit/test_snapshots.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'pare_frida_mcp.core.snapshots'`.

- [ ] **Step 3: Implement the module**

Create `src/pare_frida_mcp/core/snapshots.py`:

```python
from __future__ import annotations

from collections import OrderedDict

from pare_frida_mcp.capture.store import CaptureStore

SNAPSHOT_HANDLE = "@snapshots"  # reserved; not a valid session id


def snapshot_key(tool: str, **args) -> str:
    """Stable per-query key: tool plus sorted non-empty args."""
    parts = [tool] + [f"{k}={v}" for k, v in sorted(args.items()) if v not in ("", None)]
    return ":".join(parts)


class SnapshotStore:
    """Sessionless, in-memory store of latest-per-query device snapshots.

    Replace semantics: re-running a query (same key) upserts that key's rows.
    An LRU bound on distinct keys keeps a long session from growing unbounded.
    """

    def __init__(self, max_keys: int = 32):
        self.store = CaptureStore.open_memory()
        self._keys: "OrderedDict[str, None]" = OrderedDict()
        self._max_keys = max_keys

    def replace(self, source: str, items: list[dict], summary_field: str = "name") -> int:
        self.store.delete_by_source(source)
        for item in items:
            self.store.write({
                "type": "snapshot",
                "source": source,
                "summary": str(item.get(summary_field, "")),
                "payload": item,
            })
        self._keys.pop(source, None)
        self._keys[source] = None  # mark most-recently-used
        while len(self._keys) > self._max_keys:
            old, _ = self._keys.popitem(last=False)
            self.store.delete_by_source(old)
        return len(items)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `PYTHONPATH=src python3 -m pytest tests/unit/test_snapshots.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/pare_frida_mcp/core/snapshots.py tests/unit/test_snapshots.py
git commit -m "feat(snapshots): SnapshotStore with per-query replace and LRU bound

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Handler routing for `@snapshots`

**Files:**
- Modify: `src/pare_frida_mcp/tools.py`
- Test: `tests/unit/test_snapshot_routing.py` (create)

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_snapshot_routing.py`:

```python
import json
import pytest

from pare_frida_mcp import tools as T
from pare_frida_mcp.capture.store import CaptureStore
from pare_frida_mcp.core.snapshots import SNAPSHOT_HANDLE
from pare_frida_mcp.ids import new_session_id


class DummySession:
    def __init__(self, store):
        self.store = store
        self.flushed = False

    def flush(self):
        self.flushed = True


def test_resolve_store_routes_snapshot_handle():
    store, s = T._resolve_store(SNAPSHOT_HANDLE)
    assert store is T.SNAPSHOTS.store
    assert s is None


def test_resolve_store_routes_session_id():
    sid = new_session_id()
    dummy = DummySession(CaptureStore.open_memory())
    T.MANAGER._sessions[sid] = dummy
    try:
        store, s = T._resolve_store(sid)
        assert store is dummy.store
        assert s is dummy
    finally:
        T.MANAGER._sessions.pop(sid, None)


@pytest.mark.asyncio
async def test_search_capture_reads_snapshots_without_session():
    T.SNAPSHOTS.replace("enumerate_processes:device_id=D",
                        [{"pid": 1, "name": "zygote"}, {"pid": 2, "name": "system_server"}])
    res = json.loads(await T.search_capture(SNAPSHOT_HANDLE, text="zygote"))
    assert res["total"] == 1, res
    assert res.get("error") is not True


@pytest.mark.asyncio
async def test_read_capture_reads_snapshot_row_without_session():
    T.SNAPSHOTS.replace("enumerate_processes:device_id=E", [{"pid": 7, "name": "soloproc"}])
    # First snapshot row in a fresh handle search; find its seq via source search.
    found = json.loads(await T.search_capture(SNAPSHOT_HANDLE, field="source",
                                              contains="device_id=E"))
    seq = found["matches"][0]["seq"]
    res = json.loads(await T.read_capture(SNAPSHOT_HANDLE, seq=seq))
    assert "soloproc" in res["text"], res
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `PYTHONPATH=src python3 -m pytest tests/unit/test_snapshot_routing.py -v`
Expected: FAIL — `AttributeError: module 'pare_frida_mcp.tools' has no attribute '_resolve_store'`.

- [ ] **Step 3: Implement routing**

In `src/pare_frida_mcp/tools.py`:

Add the import alongside the other `core` imports near the top:

```python
from pare_frida_mcp.core.snapshots import SnapshotStore, SNAPSHOT_HANDLE
```

Add the module-level instance next to `MANAGER = SessionManager(CFG)`:

```python
SNAPSHOTS = SnapshotStore()
```

Add the resolver helper (place it after `_err`):

```python
def _resolve_store(handle: str):
    """Return (store, session). For the reserved snapshot handle, session is
    None (no pending queue to flush); otherwise resolve the session store."""
    if handle == SNAPSHOT_HANDLE:
        return SNAPSHOTS.store, None
    sid = validate_session_id(handle)
    s = MANAGER.get(sid)
    return s.store, s
```

Replace the existing `search_capture` handler (currently around `tools.py:169-183`) with:

```python
async def search_capture(session_id: str, field: str = "", contains: str = "",
                         text: str = "", byte_budget: int = 0) -> str:
    try:
        store, s = _resolve_store(session_id)
        if s is not None:
            s.flush()  # ensure pending messages are persisted before searching
        budget = byte_budget or _CAP
        res = _search_capture(
            store,
            field=field or None, contains=contains or None,
            text=text or None, byte_budget=budget,
        )
        return _ok(f"{res['total']} matches", **res)
    except Exception as e:
        return _err("search_capture failed", e)
```

Replace the existing `read_capture` handler (currently around `tools.py:186-195`) with:

```python
async def read_capture(session_id: str, seq: int, offset: int = 0, byte_budget: int = 0) -> str:
    try:
        store, s = _resolve_store(session_id)
        if s is not None:
            s.flush()
        budget = byte_budget or _CAP
        res = _read_capture(store, seq=seq, offset=offset, byte_budget=budget)
        return _ok(f"seq {seq}", **res)
    except Exception as e:
        return _err("read_capture failed", e)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `PYTHONPATH=src python3 -m pytest tests/unit/test_snapshot_routing.py tests/unit/test_capture_search.py tests/unit/test_capture_read.py -v`
Expected: PASS (new routing tests + existing capture search/read unit tests unaffected).

- [ ] **Step 5: Commit**

```bash
git add src/pare_frida_mcp/tools.py tests/unit/test_snapshot_routing.py
git commit -m "feat(tools): route search_capture/read_capture to @snapshots store

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: Document the `@snapshots` handle in the contract

**Files:**
- Modify: `src/pare_frida_mcp/contract.py`
- Test: `tests/unit/test_contract.py`

- [ ] **Step 1: Write the failing test**

Append to `tests/unit/test_contract.py`:

```python
def test_capture_tools_document_snapshot_handle():
    by_name = {s.name: s for s in TOOL_SPECS}
    assert "@snapshots" in by_name["search_capture"].description
    assert "@snapshots" in by_name["read_capture"].description
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src python3 -m pytest tests/unit/test_contract.py::test_capture_tools_document_snapshot_handle -v`
Expected: FAIL — `@snapshots` not in the descriptions.

- [ ] **Step 3: Update the two descriptions**

In `src/pare_frida_mcp/contract.py`, change the `search_capture` and `read_capture` `ToolSpec` description strings (currently `"Search captured events."` and `"Read a captured record slice."`) to:

- `search_capture` → `"Search captured events for a session, or device snapshots via the reserved handle '@snapshots'."`
- `read_capture` → `"Read a captured record slice for a session, or a device snapshot record via the reserved handle '@snapshots'."`

- [ ] **Step 4: Run test to verify it passes**

Run: `PYTHONPATH=src python3 -m pytest tests/unit/test_contract.py -v`
Expected: PASS (all contract tests).

- [ ] **Step 5: Commit**

```bash
git add src/pare_frida_mcp/contract.py tests/unit/test_contract.py
git commit -m "docs(contract): note @snapshots handle on search_capture/read_capture

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: Full-suite verification

- [ ] **Step 1: Run the whole unit + integration suite**

Run: `PYTHONPATH=src python3 -m pytest tests/unit tests/integration -v`
Expected: PASS (device tests skip without an emulator). Confirm no regression in `tests/integration/test_conformance.py`, `test_server_list_tools.py`, `test_wire_risk_tier.py` — none of those assert tool counts, and this feature adds no tool.

- [ ] **Step 2: Confirm the worker still imports and builds the server**

Run: `PYTHONPATH=src python3 -c "from pare_frida_mcp.server import build_server; build_server(); print('ok')"`
Expected: prints `ok` (the new `SNAPSHOTS` module-level instance constructs an in-memory store at import time without error).

- [ ] **Step 3: Final commit if anything is outstanding**

```bash
git status
# commit any stragglers; otherwise nothing to do
```

---

## Notes for the implementer

- **Why FTS `rebuild`, not `delete`:** see `delete_by_source`'s docstring and the spec. The orphaned-index bug is real for external-content FTS5; `test_delete_by_source_removes_rows_and_fts_entries` is the guard — do not weaken it.
- **The search/read engine does not change.** `search.py`/`read.py` already take a `CaptureStore` object; only the `tools.py` handlers resolve which store. If you find yourself editing `capture/search.py` or `capture/read.py`, stop — that's out of scope.
- **No new MCP tool, no risk-tier change.** This is infrastructure. The enumerate tools that write snapshots are a separate follow-up.
- **`SNAPSHOTS` is process-global.** The routing tests share it; that's fine because each uses a distinct source key. Don't add teardown that closes it.
