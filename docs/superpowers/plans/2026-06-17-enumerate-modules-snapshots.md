# enumerate_modules/exports → @snapshots Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Convert `enumerate_modules` and `enumerate_exports` from inline-capped returns to handle-only `@snapshots` consumers (persist-then-search), matching `enumerate_processes`/`applications`.

**Architecture:** Each tool persists its full list to the process-global `SnapshotStore` under a session-scoped key and returns only `{store, source, total}`. Supporting correctness fixes land first: `LIKE ? ESCAPE` for source-key matching, and a `delete_sessions` purge so a detached session's snapshots don't linger. Docs (this repo + the cross-repo PARE quickstart) move with the code.

**Tech Stack:** Python 3.12, FastMCP, SQLite (in-memory snapshot store + FTS5), pytest/pytest-asyncio.

**Spec:** `docs/superpowers/specs/2026-06-17-enumerate-modules-snapshots-design.md`

**Branch:** `feat/enumerate-modules-snapshots` (already created; spec already committed).

**Test interpreter:** Use PARE's venv, which has `pare_frida_mcp` (editable), `agent_core`, and `frida`: `~/Projects/PARE/.venv/bin/python -m pytest`. The system `python3` lacks these.

---

## File Structure

- `src/pare_frida_mcp/capture/search.py` — **modify**: escape `LIKE` metacharacters in the `field=`/`contains=` path.
- `src/pare_frida_mcp/core/snapshots.py` — **modify**: add `SnapshotStore.delete_sessions(session_id)`.
- `src/pare_frida_mcp/tools.py` — **modify**: rewrite `enumerate_modules` / `enumerate_exports` bodies; add the snapshot purge to the `detach` handler.
- `src/pare_frida_mcp/contract.py` — **modify**: drop `filter` from `enumerate_modules` `input_schema`; reword both descriptions.
- `tests/unit/test_enumerate_snapshots.py` — **create**: all new-shape + edge/error/schema unit coverage.
- `tests/unit/test_ok_floor_data_loss.py` — **modify**: remove the two now-obsolete inline-shape tests + the `memory_mod` import.
- `tests/device/test_android_flows.py` — **modify**: rewrite `test_attach_enumerate_read` for the handle-only shape.
- `docs/superpowers/tool-output-policy.md` — **modify**: flip the modules/exports status; drop "standout gap" prose.
- `README.md` — **verify-only** (expected no-op).
- `~/Projects/PARE/docs/frida-quickstart.md` (PARE repo) — **modify**: full tool-table reconciliation; separate commit.

> **Layering note (refines the spec):** the spec listed `core/sessions.py` for the detach purge. `SessionManager` has no reference to the snapshot store (a `tools.py` global), so the purge lives in the `tools.py` `detach` handler instead. `SessionManager` stays snapshot-agnostic.

---

### Task 1: Escape `LIKE` metacharacters in `search_capture`

`field='source', contains=<key>` is a raw `LIKE '%key%'`. Snapshot keys contain `_` (every `enumerate_*` name; most Android lib names), which `LIKE` treats as "any char", so one key can over-match a sibling. Add `ESCAPE` and escape `_`/`%`/`\`.

**Files:**
- Modify: `src/pare_frida_mcp/capture/search.py:59-65`
- Test: `tests/unit/test_enumerate_snapshots.py` (create)

- [ ] **Step 1: Write the failing test** (create the file)

```python
import json
import pytest

from pare_frida_mcp import tools as T
from pare_frida_mcp.core import memory as memory_mod
from pare_frida_mcp.capture.store import CaptureStore
from pare_frida_mcp.core.snapshots import snapshot_key
from pare_frida_mcp.ids import new_session_id


class _DummySession:
    """Minimal stand-in for a live Session: enough surface for the enumerate
    and detach handlers. frida_session=None so MANAGER.detach skips fs.detach;
    flush() is a no-op; store is a real in-memory CaptureStore."""
    def __init__(self):
        self.script = object()
        self.frida_session = None
        self.store = CaptureStore.open_memory()

    def flush(self):
        pass


@pytest.mark.asyncio
async def test_source_contains_escapes_like_metachars():
    # Two sources differing only at an underscore position. Unescaped, the '_'
    # in lib_x would also match libQx; with ESCAPE it must match only lib_x.
    T.SNAPSHOTS.replace("enumerate_exports:module=lib_x:session=s1", [{"name": "f1"}])
    T.SNAPSHOTS.replace("enumerate_exports:module=libQx:session=s1", [{"name": "f2"}])
    res = json.loads(await T.search_capture(
        "@snapshots", field="source",
        contains="enumerate_exports:module=lib_x:session=s1"))
    assert res["total"] == 1, res
    assert all("lib_x" in m["source"] for m in res["matches"]), res
```

- [ ] **Step 2: Run it to verify it fails**

Run: `cd ~/Projects/pare-frida-mcp && ~/Projects/PARE/.venv/bin/python -m pytest tests/unit/test_enumerate_snapshots.py::test_source_contains_escapes_like_metachars -v`
Expected: FAIL — `assert res["total"] == 1` sees `2` (the `_` over-matches `libQx`).

- [ ] **Step 3: Add escaping in `search.py`**

Replace the `elif` branch body (lines 59-65) so it reads:

```python
    elif field is not None and contains is not None:
        if field not in _ALLOWED_FIELDS:
            raise ValueError(f"field not searchable: {field!r}")
        # Escape LIKE metacharacters so a key containing '_' or '%' (snapshot
        # source keys do, via quote()) matches literally, not as a wildcard.
        esc = contains.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
        like = f"%{esc}%"
        count_sql = f"SELECT count(*) AS c FROM messages WHERE {field} LIKE ? ESCAPE '\\'"
        ids_sql = f"SELECT seq FROM messages WHERE {field} LIKE ? ESCAPE '\\' ORDER BY seq"
        params = (like,)
```

- [ ] **Step 4: Run it to verify it passes**

Run: `cd ~/Projects/pare-frida-mcp && ~/Projects/PARE/.venv/bin/python -m pytest tests/unit/test_enumerate_snapshots.py::test_source_contains_escapes_like_metachars -v`
Expected: PASS.

- [ ] **Step 5: Run the existing search tests to confirm no regression**

Run: `~/Projects/PARE/.venv/bin/python -m pytest tests/unit/test_ok_floor_data_loss.py -v`
Expected: PASS (the `contains="big"` path has no metachars; behavior unchanged).

- [ ] **Step 6: Commit**

```bash
git add src/pare_frida_mcp/capture/search.py tests/unit/test_enumerate_snapshots.py
git commit -m "fix(search): escape LIKE metacharacters in field/contains source matching"
```

---

### Task 2: `SnapshotStore.delete_sessions` purge helper

The store only deletes by *exact* source. Add a helper that purges every snapshot whose key carries `session=<sid>`, for the detach hook.

**Files:**
- Modify: `src/pare_frida_mcp/core/snapshots.py` (add method after `replace`)
- Test: `tests/unit/test_enumerate_snapshots.py`

- [ ] **Step 1: Write the failing test** (append to the test file)

```python
from pare_frida_mcp.core.snapshots import SnapshotStore


def test_delete_sessions_purges_only_that_session():
    store = SnapshotStore()
    a = snapshot_key("enumerate_modules", session="sid-a")
    a_exp = snapshot_key("enumerate_exports", session="sid-a", module="libc.so")
    b = snapshot_key("enumerate_modules", session="sid-b")
    store.replace(a, [{"name": "libc.so"}])
    store.replace(a_exp, [{"name": "open"}])
    store.replace(b, [{"name": "libm.so"}])

    removed = store.delete_sessions("sid-a")

    assert removed == 2                      # a and a_exp, not b
    assert store.latest_source() == b        # only sid-b's key remains tracked

    def _count(source):
        return store.store._conn.execute(
            "SELECT count(*) c FROM messages WHERE source=?", (source,)).fetchone()["c"]
    assert _count(a) == 0 and _count(a_exp) == 0   # sid-a purged
    assert _count(b) == 1                            # sid-b survives
```

> Note: this test reaches into `store.store._conn` for a direct row count — acceptable in a unit test pinning store internals.

- [ ] **Step 2: Run it to verify it fails**

Run: `~/Projects/PARE/.venv/bin/python -m pytest tests/unit/test_enumerate_snapshots.py::test_delete_sessions_purges_only_that_session -v`
Expected: FAIL — `AttributeError: 'SnapshotStore' object has no attribute 'delete_sessions'`.

- [ ] **Step 3: Implement `delete_sessions`** (add after `replace`, before `latest_source`)

```python
    def delete_sessions(self, session_id: str) -> int:
        """Purge every snapshot keyed to a session (called on detach).

        Module/export snapshot keys embed `session=<sid>`; a torn-down
        session's maps must not stay queryable (a stale view is simply wrong).
        Matches the percent-encoded `session=<sid>` segment, which is delimited
        by ':' and cannot contain ':' itself, so the substring test is safe.
        """
        needle = f"session={quote(str(session_id), safe='')}"
        victims = [k for k in self._keys if needle in k]
        for k in victims:
            self.store.delete_by_source(k)
            self._keys.pop(k, None)
        return len(victims)
```

(`quote` is already imported at the top of `snapshots.py`.)

- [ ] **Step 4: Run it to verify it passes**

Run: `~/Projects/PARE/.venv/bin/python -m pytest tests/unit/test_enumerate_snapshots.py::test_delete_sessions_purges_only_that_session -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/pare_frida_mcp/core/snapshots.py tests/unit/test_enumerate_snapshots.py
git commit -m "feat(snapshots): delete_sessions purges a session's snapshots"
```

---

### Task 3: `enumerate_modules` → handle-only

**Files:**
- Modify: `src/pare_frida_mcp/tools.py:153-163` (the `enumerate_modules` body + signature)
- Modify: `src/pare_frida_mcp/contract.py:57-58`
- Modify: `tests/unit/test_ok_floor_data_loss.py` (remove the obsolete modules test)
- Test: `tests/unit/test_enumerate_snapshots.py`

- [ ] **Step 1: Remove the obsolete inline-shape modules test**

In `tests/unit/test_ok_floor_data_loss.py`, delete `test_enumerate_modules_returns_bounded_list_not_empty_fallback` (lines 27-40) entirely. (Its premise — a bounded inline list — no longer exists. New coverage lives in `test_enumerate_snapshots.py`.) Leave the `memory_mod` import for now; the exports test below still uses it.

- [ ] **Step 2: Write the failing new-shape test** (append to `test_enumerate_snapshots.py`)

```python
@pytest.mark.asyncio
async def test_enumerate_modules_handle_only(monkeypatch):
    sid = new_session_id()
    T.MANAGER._sessions[sid] = _DummySession()
    monkeypatch.setattr(memory_mod, "enumerate_modules",
                        lambda script: [{"name": f"lib{i}.so", "base": hex(i), "size": i}
                                        for i in range(300)])
    res = json.loads(await T.enumerate_modules(sid))
    assert res["store"] == "@snapshots", res
    assert res["total"] == 300, res
    assert "modules" not in res, res                 # handle-only, no inline list
    key = res["source"]
    assert key == snapshot_key("enumerate_modules", session=sid)
    # All 300 rows persisted under that key (uncapped).
    got = json.loads(await T.search_capture("@snapshots", field="source",
                                            contains=key, count_only=True))
    assert got["total"] == 300, got
```

- [ ] **Step 3: Run it to verify it fails**

Run: `~/Projects/PARE/.venv/bin/python -m pytest tests/unit/test_enumerate_snapshots.py::test_enumerate_modules_handle_only -v`
Expected: FAIL — the old body calls `enumerate_modules(script, filter or None)` (2 args) against the 1-arg monkeypatch → `TypeError`, swallowed into an `_err` envelope, so `res["store"]` is missing.

- [ ] **Step 4: Rewrite the `enumerate_modules` body** in `tools.py`

Replace lines 153-163 with:

```python
async def enumerate_modules(session_id: str) -> str:
    try:
        sid = validate_session_id(session_id)
        s = MANAGER.get(sid)
        # Session-scoped key: modules are meaningful only relative to THIS
        # attached process, so the key must not collide across sessions.
        key = snapshot_key("enumerate_modules", session=sid)
        # Persist the FULL list uncapped (persist-then-search); return only a
        # handle. /snapshot shows all; a text= search narrows. No fit_items.
        mods = memory_mod.enumerate_modules(s.script)
        n = SNAPSHOTS.replace(key, mods, summary_field="name")
        return _ok(f"{n} modules captured to @snapshots. Run /snapshot to view "
                   f"the full list, or search_capture(session_id='@snapshots', "
                   f"text='<lib-or-symbol>') to find specific entries.",
                   store=SNAPSHOT_HANDLE, source=key, total=n)
    except Exception as e:
        return _err("enumerate_modules failed", e)
```

- [ ] **Step 5: Drop `filter` from the contract** — `contract.py:57-58` becomes:

```python
    ToolSpec("enumerate_modules", "low",
             "List modules loaded in an ATTACHED process into the @snapshots "
             "store (requires session_id from attach). Returns a source key; "
             "view the full list with /snapshot, or narrow with "
             "search_capture(session_id='@snapshots', text=<lib-or-symbol>).",
             _in(session_id={"type": "string"})),
```

- [ ] **Step 6: Run the new test + the floor file**

Run: `~/Projects/PARE/.venv/bin/python -m pytest tests/unit/test_enumerate_snapshots.py::test_enumerate_modules_handle_only tests/unit/test_ok_floor_data_loss.py -v`
Expected: PASS (new test green; floor file green with the modules test removed).

- [ ] **Step 7: Commit**

```bash
git add src/pare_frida_mcp/tools.py src/pare_frida_mcp/contract.py tests/unit/test_enumerate_snapshots.py tests/unit/test_ok_floor_data_loss.py
git commit -m "feat(tools): enumerate_modules persists to @snapshots (handle-only); drop filter="
```

---

### Task 4: `enumerate_exports` → handle-only

**Files:**
- Modify: `src/pare_frida_mcp/tools.py:166-176`
- Modify: `src/pare_frida_mcp/contract.py:59-60`
- Modify: `tests/unit/test_ok_floor_data_loss.py` (remove the obsolete exports test + now-unused import)
- Test: `tests/unit/test_enumerate_snapshots.py`

- [ ] **Step 1: Remove the obsolete inline-shape exports test + import**

In `tests/unit/test_ok_floor_data_loss.py`, delete `test_enumerate_exports_returns_bounded_list_not_empty_fallback` (lines 43-55) and remove the now-unused `from pare_frida_mcp.core import memory as memory_mod` import (line 11).

- [ ] **Step 2: Write the failing new-shape test** (append to `test_enumerate_snapshots.py`)

```python
@pytest.mark.asyncio
async def test_enumerate_exports_handle_only(monkeypatch):
    sid = new_session_id()
    T.MANAGER._sessions[sid] = _DummySession()
    monkeypatch.setattr(memory_mod, "enumerate_exports",
                        lambda script, module: [{"name": f"sym{i}", "address": hex(i)}
                                                for i in range(120)])
    res = json.loads(await T.enumerate_exports(sid, module="libc.so"))
    assert res["store"] == "@snapshots", res
    assert res["total"] == 120, res
    assert "exports" not in res, res
    assert res["source"] == snapshot_key("enumerate_exports", session=sid, module="libc.so")
```

- [ ] **Step 3: Run it to verify it fails**

Run: `~/Projects/PARE/.venv/bin/python -m pytest tests/unit/test_enumerate_snapshots.py::test_enumerate_exports_handle_only -v`
Expected: FAIL — old body returns the inline `exports=[…]` shape, so `res["store"]` is missing.

- [ ] **Step 4: Rewrite the `enumerate_exports` body** in `tools.py`

Replace lines 166-176 with:

```python
async def enumerate_exports(session_id: str, module: str) -> str:
    try:
        sid = validate_session_id(session_id)
        s = MANAGER.get(sid)
        # module= is part of the key so each module's exports get their own
        # snapshot; session= scopes it to this attached process.
        key = snapshot_key("enumerate_exports", session=sid, module=module)
        exps = memory_mod.enumerate_exports(s.script, module)
        n = SNAPSHOTS.replace(key, exps, summary_field="name")
        return _ok(f"{n} exports for {module} captured to @snapshots. Run "
                   f"/snapshot to view the full list, or "
                   f"search_capture(session_id='@snapshots', text='<symbol>') "
                   f"to find specific entries.",
                   store=SNAPSHOT_HANDLE, source=key, total=n)
    except Exception as e:
        return _err("enumerate_exports failed", e)
```

- [ ] **Step 5: Update the contract description** — `contract.py:59-60` becomes:

```python
    ToolSpec("enumerate_exports", "low",
             "List a module's exports in an ATTACHED process into the "
             "@snapshots store (requires session_id from attach). Returns a "
             "source key; view with /snapshot or narrow with "
             "search_capture(session_id='@snapshots', text=<symbol>).",
             _in(session_id={"type": "string"}, module={"type": "string"})),
```

- [ ] **Step 6: Run the new test + the floor file**

Run: `~/Projects/PARE/.venv/bin/python -m pytest tests/unit/test_enumerate_snapshots.py::test_enumerate_exports_handle_only tests/unit/test_ok_floor_data_loss.py -v`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/pare_frida_mcp/tools.py src/pare_frida_mcp/contract.py tests/unit/test_enumerate_snapshots.py tests/unit/test_ok_floor_data_loss.py
git commit -m "feat(tools): enumerate_exports persists to @snapshots (handle-only)"
```

---

### Task 5: `detach` purges the session's snapshots

**Files:**
- Modify: `src/pare_frida_mcp/tools.py` (the `detach` handler, ~lines 72-82)
- Test: `tests/unit/test_enumerate_snapshots.py`

- [ ] **Step 1: Write the failing test** (append)

```python
@pytest.mark.asyncio
async def test_detach_purges_session_snapshots():
    sid = new_session_id()
    T.MANAGER._sessions[sid] = _DummySession()
    key = snapshot_key("enumerate_modules", session=sid)
    other = snapshot_key("enumerate_modules", session="other-sid")
    T.SNAPSHOTS.replace(key, [{"name": "libc.so"}])
    T.SNAPSHOTS.replace(other, [{"name": "libm.so"}])

    res = json.loads(await T.detach(sid))
    assert res.get("session_id") == sid, res

    gone = json.loads(await T.search_capture("@snapshots", field="source",
                                             contains=key, count_only=True))
    assert gone["total"] == 0, gone
    survives = json.loads(await T.search_capture("@snapshots", field="source",
                                                 contains=other, count_only=True))
    assert survives["total"] == 1, survives
```

- [ ] **Step 2: Run it to verify it fails**

Run: `~/Projects/PARE/.venv/bin/python -m pytest tests/unit/test_enumerate_snapshots.py::test_detach_purges_session_snapshots -v`
Expected: FAIL — `gone["total"]` is `1`; detach doesn't purge yet.

- [ ] **Step 3: Add the purge to the `detach` handler** in `tools.py`

The handler currently is:

```python
async def detach(session_id: str) -> str:
    try:
        sid = validate_session_id(session_id)
        MANAGER.detach(sid)
        return _ok(f"detached {sid}", session_id=sid)
    except KeyError:
        return _err(f"no such session {session_id!r}")
    except Exception as e:
        return _err("detach failed", e)
```

Add one line after `MANAGER.detach(sid)`:

```python
        MANAGER.detach(sid)
        # A torn-down session's module/export snapshots must not linger
        # queryable (stale == wrong). Re-attach starts fresh snapshots.
        SNAPSHOTS.delete_sessions(sid)
```

- [ ] **Step 4: Run it to verify it passes**

Run: `~/Projects/PARE/.venv/bin/python -m pytest tests/unit/test_enumerate_snapshots.py::test_detach_purges_session_snapshots -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/pare_frida_mcp/tools.py tests/unit/test_enumerate_snapshots.py
git commit -m "feat(tools): detach purges the session's @snapshots"
```

---

### Task 6: Edge-case, error-path, and schema unit tests

Pin the behaviors the spec claims but the happy-path tests don't cover.

**Files:**
- Test: `tests/unit/test_enumerate_snapshots.py` (append all of the below)

- [ ] **Step 1: Write the tests**

```python
@pytest.mark.asyncio
async def test_enumerate_modules_no_live_session_errors():
    sid = new_session_id()  # well-formed but never registered
    res = json.loads(await T.enumerate_modules(sid))
    assert res.get("error") is True, res
    assert "source" not in res, res


@pytest.mark.asyncio
async def test_enumerate_exports_no_live_session_errors():
    sid = new_session_id()
    res = json.loads(await T.enumerate_exports(sid, module="libc.so"))
    assert res.get("error") is True, res


@pytest.mark.asyncio
async def test_enumerate_modules_empty_list(monkeypatch):
    sid = new_session_id()
    T.MANAGER._sessions[sid] = _DummySession()
    monkeypatch.setattr(memory_mod, "enumerate_modules", lambda script: [])
    res = json.loads(await T.enumerate_modules(sid))
    assert res.get("error") is not True, res
    assert res["total"] == 0, res
    assert res["source"]


@pytest.mark.asyncio
async def test_reenumerate_refreshes_same_key(monkeypatch):
    sid = new_session_id()
    T.MANAGER._sessions[sid] = _DummySession()
    monkeypatch.setattr(memory_mod, "enumerate_modules",
                        lambda script: [{"name": "a.so"}, {"name": "b.so"}])
    r1 = json.loads(await T.enumerate_modules(sid))
    monkeypatch.setattr(memory_mod, "enumerate_modules",
                        lambda script: [{"name": "c.so"}])
    r2 = json.loads(await T.enumerate_modules(sid))
    assert r1["source"] == r2["source"], (r1, r2)   # same session-scoped key
    assert r2["total"] == 1
    got = json.loads(await T.search_capture("@snapshots", field="source",
                                            contains=r2["source"]))
    names = {json.loads(m["payload"])["name"] for m in got["matches"]}
    assert names == {"c.so"}, got                    # only new rows; old replaced


@pytest.mark.asyncio
async def test_exports_distinct_module_keys_coexist(monkeypatch):
    sid = new_session_id()
    T.MANAGER._sessions[sid] = _DummySession()
    monkeypatch.setattr(memory_mod, "enumerate_exports",
                        lambda script, module: [{"name": module + ":f"}])
    ra = json.loads(await T.enumerate_exports(sid, module="liba.so"))
    rb = json.loads(await T.enumerate_exports(sid, module="libb.so"))
    assert ra["source"] != rb["source"]
    ga = json.loads(await T.search_capture("@snapshots", field="source",
                                           contains=ra["source"], count_only=True))
    gb = json.loads(await T.search_capture("@snapshots", field="source",
                                           contains=rb["source"], count_only=True))
    assert ga["total"] == 1 and gb["total"] == 1, (ga, gb)


def test_filter_removed_from_schema():
    from pare_frida_mcp.contract import TOOL_SPECS
    mods = next(s for s in TOOL_SPECS if s.name == "enumerate_modules")
    assert "filter" not in mods.input_schema["properties"], mods.input_schema
    exps = next(s for s in TOOL_SPECS if s.name == "enumerate_exports")
    assert "module" in exps.input_schema["properties"], exps.input_schema
```

- [ ] **Step 2: Run them**

Run: `~/Projects/PARE/.venv/bin/python -m pytest tests/unit/test_enumerate_snapshots.py -v`
Expected: PASS (all of Tasks 1-6 green).

- [ ] **Step 3: Commit**

```bash
git add tests/unit/test_enumerate_snapshots.py
git commit -m "test(snapshots): edge, error-path, and schema coverage for enumerate tools"
```

---

### Task 7: Rewrite the device test for the handle-only shape

The existing `test_attach_enumerate_read` read the inline `mods["modules"]` list and fed `libc["base"]` into `read_memory`. Recover `base` from the persisted snapshot instead, and assert the *uncapped* persist.

**Files:**
- Modify: `tests/device/test_android_flows.py:13-27`

> Device-gated: requires the emulator + `frida-server` (root). Skips cleanly otherwise.

- [ ] **Step 1: Replace `test_attach_enumerate_read`** with:

```python
@pytest.mark.asyncio
async def test_attach_enumerate_read(system_server_pid):
    res = json.loads(await T.attach(target=str(system_server_pid)))
    assert "session_id" in res, res
    sid = res["session_id"]
    try:
        mods = json.loads(await T.enumerate_modules(sid))
        assert mods["store"] == "@snapshots", mods
        assert mods["total"] > 50, mods            # full list persisted, uncapped
        # Recover libc's base from the snapshot via a NARROW search (the
        # intended persist-then-search usage), then read its memory.
        found = json.loads(await T.search_capture("@snapshots", text="libc"))
        assert found["total"] >= 1, found
        libc = next((p for p in (json.loads(m["payload"]) for m in found["matches"])
                     if "libc" in p["name"]), None)
        assert libc is not None, found
        mem = json.loads(await T.read_memory(sid, address=libc["base"], size=16))
        assert mem.get("hex_preview"), mem
    finally:
        # Detach via the underlying frida session to free emulator resources.
        T.MANAGER.get(sid).frida_session.detach()
```

- [ ] **Step 2: Run the device suite (with the emulator up + root frida-server)**

Run: `cd ~/Projects/pare-frida-mcp && ~/Projects/PARE/.venv/bin/python -m pytest tests/device/test_android_flows.py -v`
Expected: PASS if a USB device is present; SKIP otherwise. If it errors with `ServerNotRunningError: closed`, frida-server isn't running as root — restart it (`adb shell su -c '/data/local/tmp/frida-server -D'`) and re-run.

- [ ] **Step 3: Commit**

```bash
git add tests/device/test_android_flows.py
git commit -m "test(device): enumerate_read uses the handle-only @snapshots shape"
```

---

### Task 8: Update `tool-output-policy.md` (this repo)

**Files:**
- Modify: `docs/superpowers/tool-output-policy.md` (the "Current state vs. target" table + the closing paragraph)

- [ ] **Step 1: Flip the table row.** Replace:

```markdown
| `enumerate_modules` / `enumerate_exports` | snapshot-shaped state view | **inline (large lists)** | **convert to store consumers** (next effort) |
```

with:

```markdown
| `enumerate_modules` / `enumerate_exports` | snapshot | `@snapshots` ✓ | done |
```

- [ ] **Step 2: Replace the closing "standout gap" paragraph** (the three lines beginning "The standout gap is …") with:

```markdown
`enumerate_modules` / `enumerate_exports` are now `@snapshots` consumers like
`enumerate_processes` / `applications`: session-scoped keys, full list persisted
uncapped, handle-only return. The operator reads the complete list with
`/snapshot`; the model narrows with a `text=` search. Snapshots are a bounded
LRU cache (re-enumerate to refresh), and `detach` purges a session's snapshots.
```

- [ ] **Step 3: Commit**

```bash
git add docs/superpowers/tool-output-policy.md
git commit -m "docs(policy): mark enumerate_modules/exports converted to @snapshots"
```

---

### Task 9: Verify `README.md` (expected no-op)

**Files:**
- Inspect: `README.md`

- [ ] **Step 1: Confirm no edit needed**

Run: `grep -n "enumerate\|inline\|module" README.md`
Confirm the surface description ("memory-inspection surface (enumerate / read / write)") does not promise inline module output. If it does not (expected), **make no change** and skip the commit. If it does, adjust the one line and commit with `docs(readme): note enumerate persists to @snapshots`.

---

### Task 10: Reconcile PARE's `frida-quickstart.md` tool table (cross-repo)

The PARE-side operator doc's tool table is stale: it says "13 tools", omits five, and lists wrong tiers. Reconcile the whole table against `contract.py`. **Separate repo, separate commit.**

**Files:**
- Modify: `~/Projects/PARE/docs/frida-quickstart.md:14` and the table at lines 19-31

- [ ] **Step 1: Fix the count line (14).** Replace `It exposes 13 tools; PARE registers them as` with `It exposes 18 tools; PARE registers them as`.

- [ ] **Step 2: Replace the table body (lines 19-31)** with the full set, tiers matching `contract.py`:

```markdown
| `list_devices` | low | List Frida devices |
| `select_device` | low | Select a device by id |
| `attach` | medium | Attach to a process by pid or name |
| `list_sessions` | low | List live sessions with a real liveness probe |
| `detach` | medium | Detach a live session and tear down its capture state |
| `enumerate_processes` | low | List device processes into the `@snapshots` store |
| `enumerate_applications` | low | List installed apps into the `@snapshots` store |
| `enumerate_modules` | low | List an attached process's modules into `@snapshots` |
| `enumerate_exports` | low | List a module's exports into `@snapshots` |
| `load_script` | medium | Load a bundled script export set |
| `execute_script` | **critical** | Evaluate arbitrary JS in a session |
| `java_hook` | **high** | Install an observing Java method hook |
| `java_hook_remove` | low | Remove a Java method hook |
| `read_memory` | **high** | Read target memory (hex preview) |
| `write_memory` | **high** | Write bytes to target memory |
| `search_capture` | low | Search captured events / snapshots |
| `read_capture` | low | Read a captured record slice |
| `page_capture` | low | Read ALL rows of a snapshot for `/snapshot` (complete, not sampled) |
```

- [ ] **Step 3: Update the session-lifecycle / enumerate prose** if the doc describes `enumerate_modules`/`exports` returning inline lists: state they persist to `@snapshots` (full list via `/snapshot`, narrow via `text=` search), like processes/applications. (Search the file for "enumerate" and adjust any inline-output wording.)

- [ ] **Step 4: Commit in the PARE repo**

```bash
cd ~/Projects/PARE
git checkout -b docs/frida-quickstart-tool-table
git add docs/frida-quickstart.md
git commit -m "docs(frida): reconcile tool table with contract (18 tools, tiers, @snapshots)"
```

> This is a PARE-repo branch/commit, intentionally separate from the worker change so each merges on its own.

---

### Task 11: Full-suite green + wrap-up

- [ ] **Step 1: Run the whole unit suite**

Run: `cd ~/Projects/pare-frida-mcp && ~/Projects/PARE/.venv/bin/python -m pytest tests/unit -v`
Expected: PASS (no regressions; new `test_enumerate_snapshots.py` green; `test_ok_floor_data_loss.py` green with the two tests removed).

- [ ] **Step 2: Run conformance/contract tests if present**

Run: `~/Projects/PARE/.venv/bin/python -m pytest tests -k "contract or conformance" -v`
Expected: PASS — confirms the `input_schema` change (dropped `filter`) keeps the worker contract valid.

- [ ] **Step 3: Confirm the branch is clean and review the diff**

Run: `git -C ~/Projects/pare-frida-mcp status && git -C ~/Projects/pare-frida-mcp log --oneline feat/enumerate-modules-snapshots ^main`
Expected: the task commits, working tree clean.

---

## Self-Review

- **Spec coverage:** handle-only shape (T3/T4) ✓; session-scoped keys (T3/T4) ✓; percent-encoded-key/verbatim-copy reflected in guidance strings + descriptions (T3/T4) ✓; Retrieval semantics / LIKE escape (T1) ✓; Session lifecycle / detach purge (T2/T5) ✓; drop `filter` from signature **and** schema (T3) ✓; guidance leads with `/snapshot` + `text=` (T3/T4) ✓; Known-bounds doc note (T8) ✓; code comments (T3/T4/T5 inline) ✓; tests incl. monkeypatch arity, store target, no-live-session, empty list, refresh, distinct keys, schema, device JSON recovery, large list (T3-T7) ✓; docs: tool-output-policy (T8), README verify (T9), PARE table reconciliation (T10) ✓.
- **Placeholder scan:** none — every code step shows full code.
- **Type consistency:** `delete_sessions(session_id) -> int` defined T2, called T5; `snapshot_key("enumerate_modules", session=sid)` / `("enumerate_exports", session=sid, module=module)` consistent across T3/T4/tests; return keys `store`/`source`/`total` consistent across handlers and assertions.
