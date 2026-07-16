# `/snapshot` Viewer (v0) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A deterministic `/snapshot` CLI command that reads the `@snapshots` store and renders rows to the terminal — complete, exact, the LLM entirely out of the loop — via a new complete-read worker tool `page_capture`.

**Architecture:** New worker tool `page_capture` (pare-frida-mcp) returns *all* rows of a snapshot (no sampling), byte-honest, bypassing the 4096-byte model cap since the result is consumed by the command, not model context. A PARE domain command `/snapshot` calls it through the audited `tool_pool`, resolves a snapshot by latest / catalog / substring-key, and renders a width-clipped dynamic-column table. The enumerate tools advertise the command in their return string.

**Tech Stack:** Python, SQLite (`CaptureStore`), pytest (run via `/home/edible/Projects/PARE/.venv/bin/python` — `pare_frida_mcp` is editable-installed in that venv).

**Cross-repo + stacking note:** Spans two repos and **stacks on the read-only re-tier branches** (so `contract.py` stays consistent and `page_capture`'s `low` tier auto-executes under the dropped floor). Base the pare-frida-mcp branch on `feat/readonly-risk-retier`, the PARE branch on `feat/frida-floor-low`. Merge after the re-tier PRs (pare-frida-mcp#5, PARE#11).

**Spec:** `docs/superpowers/specs/2026-06-07-snapshot-viewer-command-design.md`

---

## File Structure

**pare-frida-mcp:**
- `src/pare_frida_mcp/core/snapshots.py` — **modify**: add `SnapshotStore.latest_source()`.
- `src/pare_frida_mcp/capture/page.py` — **create**: `page_rows()` (complete, byte-honest read) + `list_sources()` (catalog). Sibling to `search.py`/`read.py`.
- `src/pare_frida_mcp/tools.py` — **modify**: add `page_capture` handler.
- `src/pare_frida_mcp/contract.py` — **modify**: add `page_capture` `ToolSpec`; append `/snapshot` pointer to `enumerate_processes`/`enumerate_applications` returns lives in tools.py.
- Tests: `tests/unit/test_page.py`, `tests/unit/test_tools_page.py` (create).

**PARE:**
- `pare/commands/_snapshot_render.py` — **create**: pure `render_table()` / `render_catalog()`.
- `pare/commands/snapshot.py` — **create**: `Snapshot(Command)`.
- `pare/agent.py` — **modify**: register `Snapshot` in `commands`.
- Tests: `tests/test_snapshot_render.py`, `tests/test_snapshot_command.py` (create).

---

## Task 0: Branches

- [ ] **Step 1: Branch pare-frida-mcp off the re-tier branch**

```bash
cd /home/edible/Projects/pare-frida-mcp
git checkout feat/readonly-risk-retier
git checkout -b feat/snapshot-viewer
```

- [ ] **Step 2: Branch PARE off the floor branch**

```bash
cd /home/edible/Projects/PARE
git checkout feat/frida-floor-low
git checkout -b feat/snapshot-command
```

---

## Task 1: `SnapshotStore.latest_source()`

**Files:**
- Modify: `src/pare_frida_mcp/core/snapshots.py`
- Test: `tests/unit/test_snapshots.py` (create if absent)

- [ ] **Step 1: Write the failing test**

Create/append `tests/unit/test_snapshots.py`:

```python
from pare_frida_mcp.core.snapshots import SnapshotStore


def test_latest_source_is_most_recently_replaced():
    s = SnapshotStore()
    assert s.latest_source() is None          # empty store
    s.replace("alpha", [{"name": "a"}])
    s.replace("beta", [{"name": "b"}])
    assert s.latest_source() == "beta"        # MRU, not seq order
    s.replace("alpha", [{"name": "a2"}])      # touch alpha -> now MRU
    assert s.latest_source() == "alpha"
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd /home/edible/Projects/pare-frida-mcp && /home/edible/Projects/PARE/.venv/bin/python -m pytest tests/unit/test_snapshots.py -v`
Expected: FAIL — `AttributeError: 'SnapshotStore' object has no attribute 'latest_source'`.

- [ ] **Step 3: Implement**

In `src/pare_frida_mcp/core/snapshots.py`, add this method to `SnapshotStore` (after `replace`):

```python
    def latest_source(self) -> str | None:
        """The most-recently-replaced source key (MRU), or None if empty.

        Uses the LRU OrderedDict (insertion/touch order) rather than MAX(seq):
        seq is a reused SQLite rowid, so a replaced source can take lower seqs
        and 'highest seq' would point at the wrong snapshot.
        """
        if not self._keys:
            return None
        return next(reversed(self._keys))
```

- [ ] **Step 4: Run to verify it passes**

Run: `/home/edible/Projects/PARE/.venv/bin/python -m pytest tests/unit/test_snapshots.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/pare_frida_mcp/core/snapshots.py tests/unit/test_snapshots.py
git commit -m "feat(snapshots): latest_source() returns the MRU snapshot key"
```

---

## Task 2: `capture/page.py` — complete read + catalog

**Files:**
- Create: `src/pare_frida_mcp/capture/page.py`
- Test: `tests/unit/test_page.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_page.py`:

```python
import pytest
from pare_frida_mcp.capture.store import CaptureStore
from pare_frida_mcp.capture.page import page_rows, list_sources


def _seed(store, source, items, summary_field="name"):
    for it in items:
        store.write({"type": "snapshot", "source": source,
                     "summary": str(it.get(summary_field, "")), "payload": it})


def test_page_rows_returns_all_items_in_order():
    store = CaptureStore.open_memory()
    _seed(store, "s1", [{"name": "c"}, {"name": "a"}, {"name": "b"}])
    res = page_rows(store, source="s1")
    assert res["total"] == 3
    assert res["shown"] == 3
    assert [r["name"] for r in res["rows"]] == ["c", "a", "b"]   # seq order, unsampled


def test_page_rows_filters_on_summary_like():
    store = CaptureStore.open_memory()
    _seed(store, "apps", [{"identifier": "com.bank"}, {"identifier": "com.maps"}],
          summary_field="identifier")
    res = page_rows(store, source="apps", field="summary", contains="bank")
    assert res["total"] == 1
    assert res["rows"][0]["identifier"] == "com.bank"


def test_page_rows_rejects_unallowed_field():
    store = CaptureStore.open_memory()
    _seed(store, "s1", [{"name": "a"}])
    with pytest.raises(ValueError):
        page_rows(store, source="s1", field="payload", contains="a")


def test_page_rows_byte_honest_cap_reports_shown_vs_total():
    store = CaptureStore.open_memory()
    _seed(store, "big", [{"name": f"item-{i}", "blob": "x" * 200} for i in range(50)])
    res = page_rows(store, source="big", byte_budget=2048)   # forces a partial page
    assert res["total"] == 50
    assert 0 < res["shown"] < 50              # whole rows only, honest count
    assert all("name" in r for r in res["rows"])


def test_list_sources_catalog():
    store = CaptureStore.open_memory()
    _seed(store, "a", [{"name": "1"}, {"name": "2"}])
    _seed(store, "b", [{"name": "3"}])
    cat = list_sources(store)
    assert {"source": "a", "count": 2} in cat
    assert {"source": "b", "count": 1} in cat
```

- [ ] **Step 2: Run to verify it fails**

Run: `/home/edible/Projects/PARE/.venv/bin/python -m pytest tests/unit/test_page.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'pare_frida_mcp.capture.page'`.

- [ ] **Step 3: Implement**

Create `src/pare_frida_mcp/capture/page.py`:

```python
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
```

- [ ] **Step 4: Run to verify it passes**

Run: `/home/edible/Projects/PARE/.venv/bin/python -m pytest tests/unit/test_page.py -v`
Expected: PASS (5 tests).

- [ ] **Step 5: Commit**

```bash
git add src/pare_frida_mcp/capture/page.py tests/unit/test_page.py
git commit -m "feat(capture): page.py complete byte-honest snapshot read + catalog"
```

---

## Task 3: `page_capture` worker tool (handler + spec)

**Files:**
- Modify: `src/pare_frida_mcp/tools.py` (add handler + import)
- Modify: `src/pare_frida_mcp/contract.py` (add ToolSpec)
- Test: `tests/unit/test_tools_page.py`

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_tools_page.py`:

```python
import json
import pytest
from pare_frida_mcp import tools as T


@pytest.mark.asyncio
async def test_page_capture_returns_complete_rows_for_latest():
    T.SNAPSHOTS.replace("enumerate_applications:device=emu",
                        [{"identifier": "com.bank"}, {"identifier": "com.maps"}],
                        summary_field="identifier")
    out = json.loads(await T.page_capture("@snapshots"))   # source omitted -> latest
    assert out["store"] == "@snapshots"
    assert out["source"] == "enumerate_applications:device=emu"
    assert out["total"] == 2
    assert {r["identifier"] for r in out["rows"]} == {"com.bank", "com.maps"}


@pytest.mark.asyncio
async def test_page_capture_filters_by_summary():
    T.SNAPSHOTS.replace("apps:1", [{"identifier": "com.bank"}, {"identifier": "com.maps"}],
                        summary_field="identifier")
    out = json.loads(await T.page_capture("@snapshots", source="apps:1",
                                          field="summary", contains="bank"))
    assert out["total"] == 1
    assert out["rows"][0]["identifier"] == "com.bank"


@pytest.mark.asyncio
async def test_page_capture_list_sources():
    T.SNAPSHOTS.replace("k1", [{"name": "a"}])
    out = json.loads(await T.page_capture("@snapshots", list_sources=True))
    assert any(s["source"] == "k1" for s in out["sources"])


@pytest.mark.asyncio
async def test_page_capture_empty_store_is_graceful(monkeypatch):
    monkeypatch.setattr(T, "SNAPSHOTS", type(T.SNAPSHOTS)())   # fresh empty store
    out = json.loads(await T.page_capture("@snapshots"))
    assert out.get("total", 0) == 0 or "sources" in out
```

- [ ] **Step 2: Run to verify it fails**

Run: `/home/edible/Projects/PARE/.venv/bin/python -m pytest tests/unit/test_tools_page.py -v`
Expected: FAIL — `AttributeError: module 'pare_frida_mcp.tools' has no attribute 'page_capture'`.

- [ ] **Step 3: Implement the handler**

In `src/pare_frida_mcp/tools.py`, add the import near the other capture imports (after line 14):

```python
from pare_frida_mcp.capture.page import page_rows as _page_rows, list_sources as _list_sources
```

Add this constant near `_CAP` (after line 22):

```python
# page_capture is consumed by the /snapshot command, NOT model context, so it
# is exempt from the 4096-byte model cap. Bound to a generous budget instead.
_PAGE_BUDGET = 262144
```

Add the handler (place it right after `read_capture`, near line 267):

```python
async def page_capture(session_id: str, source: str = "", field: str = "",
                       contains: str = "", list_sources: bool = False) -> str:
    try:
        store, _ = _resolve_store(session_id)
        if list_sources:
            srcs = _list_sources(store)
            return json.dumps({"summary": f"{len(srcs)} snapshots",
                               "store": session_id, "sources": srcs})
        # Latest resolution is @snapshots-specific (MRU); v0 only uses @snapshots.
        src = source or (SNAPSHOTS.latest_source() if session_id == SNAPSHOT_HANDLE else "")
        if not src:
            return json.dumps({"summary": "no snapshots captured yet",
                               "store": session_id, "sources": []})
        res = _page_rows(store, source=src, field=field or None,
                         contains=contains or None, byte_budget=_PAGE_BUDGET)
        summary = f"{res['shown']} of {res['total']} rows for {src}"
        # Direct json.dumps (NOT _ok): intentionally bypasses the model cap.
        return json.dumps({"summary": summary, "store": session_id, "source": src,
                           "rows": res["rows"], "total": res["total"],
                           "shown": res["shown"]})
    except Exception as e:
        return _err("page_capture failed", e)
```

- [ ] **Step 4: Run to verify it passes**

Run: `/home/edible/Projects/PARE/.venv/bin/python -m pytest tests/unit/test_tools_page.py -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Add the ToolSpec**

In `src/pare_frida_mcp/contract.py`, add after the `read_capture` ToolSpec (the description steers the *model* to `search_capture` so the uncapped tool stays a command/human path):

```python
    ToolSpec("page_capture", "low",
             "Read ALL rows of a snapshot from a capture store (COMPLETE, not "
             "sampled) for human display via the /snapshot command. "
             "session_id='@snapshots'; omit source for the latest snapshot, or "
             "pass source=<key> with field='summary', contains=<substring> to "
             "filter; list_sources=true returns the catalog. Models should use "
             "search_capture instead (this returns unbounded output).",
             _in(session_id={"type": "string"}, source={"type": "string"},
                 field={"type": "string"}, contains={"type": "string"},
                 list_sources={"type": "boolean"})),
```

- [ ] **Step 6: Verify contract + tools still pass**

Run: `/home/edible/Projects/PARE/.venv/bin/python -m pytest tests/unit/test_contract.py tests/unit/test_tools_page.py -q`
Expected: PASS. (`test_every_tool_has_required_metadata` now also covers `page_capture`.)

- [ ] **Step 7: Commit**

```bash
git add src/pare_frida_mcp/tools.py src/pare_frida_mcp/contract.py tests/unit/test_tools_page.py
git commit -m "feat(tools): page_capture worker tool (complete snapshot read)"
```

---

## Task 4: PARE renderer (pure functions)

**Files:**
- Create: `pare/commands/_snapshot_render.py`
- Test: `tests/test_snapshot_render.py`

- [ ] **Step 1: Write the failing test**

Create `PARE/tests/test_snapshot_render.py`:

```python
from pare.commands._snapshot_render import render_table, render_catalog


def test_render_table_dynamic_columns_and_header():
    rows = [{"identifier": "com.bank", "name": "Bank", "pid": 0},
            {"identifier": "com.maps", "name": "Maps", "pid": 11}]
    out = render_table(rows)
    assert "identifier" in out and "name" in out and "pid" in out
    assert "com.bank" in out and "com.maps" in out


def test_render_table_clips_to_width():
    rows = [{"name": "x" * 300}]
    out = render_table(rows, max_width=80)
    assert all(len(line) <= 80 for line in out.splitlines())


def test_render_table_empty():
    assert "no rows" in render_table([]).lower()


def test_render_catalog_lists_sources_and_counts():
    out = render_catalog([{"source": "enumerate_applications:device=emu", "count": 21}])
    assert "enumerate_applications:device=emu" in out
    assert "21" in out
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd /home/edible/Projects/PARE && /home/edible/Projects/PARE/.venv/bin/python -m pytest tests/test_snapshot_render.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'pare.commands._snapshot_render'`.

- [ ] **Step 3: Implement**

Create `PARE/pare/commands/_snapshot_render.py`:

```python
"""Deterministic, width-clipped table rendering for /snapshot.

Pure functions: the command runs in the daemon and yields a string over a
socket, so it cannot see the user's TTY or spawn a pager — columns are clipped
to a conservative fixed width instead of allowed to hard-wrap.
"""
from __future__ import annotations


def _clip(value: str, width: int) -> str:
    return value if len(value) <= width else value[: max(1, width - 1)] + "…"


def render_table(rows: list[dict], max_width: int = 100) -> str:
    if not rows:
        return "(no rows)"
    cols = list(rows[0].keys())
    cell = {c: [str(r.get(c, "")) for r in rows] for c in cols}
    # Natural width per column, then shrink the widest until the line fits.
    widths = {c: max(len(c), *(len(v) for v in cell[c])) for c in cols}
    sep = 2  # spaces between columns
    def line_len() -> int:
        return sum(widths.values()) + sep * (len(cols) - 1)
    while line_len() > max_width and any(w > 6 for w in widths.values()):
        widest = max(widths, key=lambda c: widths[c])
        widths[widest] -= 1
    def fmt(vals: list[str]) -> str:
        return (" " * sep).join(_clip(v, widths[c]).ljust(widths[c])
                                for c, v in zip(cols, vals)).rstrip()
    out = [fmt(cols), fmt(["-" * widths[c] for c in cols])]
    out += [fmt([cell[c][i] for c in cols]) for i in range(len(rows))]
    return "\n".join(line[:max_width] for line in out)


def render_catalog(sources: list[dict]) -> str:
    if not sources:
        return "(no snapshots captured yet)"
    return "\n".join(f"{s['count']:>6}  {s['source']}" for s in sources)
```

- [ ] **Step 4: Run to verify it passes**

Run: `/home/edible/Projects/PARE/.venv/bin/python -m pytest tests/test_snapshot_render.py -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```bash
git add pare/commands/_snapshot_render.py tests/test_snapshot_render.py
git commit -m "feat(snapshot): width-clipped dynamic-column renderer"
```

---

## Task 5: `/snapshot` command

**Files:**
- Create: `pare/commands/snapshot.py`
- Modify: `pare/agent.py` (register in `commands`)
- Test: `tests/test_snapshot_command.py`

- [ ] **Step 1: Write the failing test**

Create `PARE/tests/test_snapshot_command.py`:

```python
import json
import pytest
from pare.commands.snapshot import Snapshot


class _Block:
    def __init__(self, text): self.type = "text"; self.text = text


class _Result:
    def __init__(self, payload): self.isError = False; self.content = [_Block(json.dumps(payload))]


class _Pool:
    """Fake tool_pool: routes page_capture calls by their arguments."""
    def __init__(self, responses): self._responses = responses; self.calls = []
    async def call_tool(self, worker, tool, args, ctx=None):
        self.calls.append((worker, tool, args))
        for matcher, payload in self._responses:
            if matcher(args):
                return _Result(payload)
        raise AssertionError(f"no canned response for {args}")


class _Ctx:
    def __init__(self, pool):
        self.agent = type("A", (), {"tool_pool": pool})()
        self.channel_id = "cli-default"


async def _collect(cmd, raw):
    return [m async for m in cmd.run(raw, cmd._ctx)]


def _cmd(responses):
    c = Snapshot()
    c._ctx = _Ctx(_Pool(responses))
    return c


@pytest.mark.asyncio
async def test_bare_snapshot_renders_latest():
    c = _cmd([(lambda a: not a.get("list_sources") and not a.get("source"),
               {"store": "@snapshots", "source": "apps:emu", "total": 1, "shown": 1,
                "rows": [{"identifier": "com.bank", "name": "Bank"}]})])
    msgs = await _collect(c, "")
    text = msgs[-1].text
    assert "com.bank" in text and "apps:emu" in text


@pytest.mark.asyncio
async def test_list_subcommand_shows_catalog():
    c = _cmd([(lambda a: a.get("list_sources"),
               {"sources": [{"source": "apps:emu", "count": 21}]})])
    msgs = await _collect(c, "list")
    assert "apps:emu" in msgs[-1].text and "21" in msgs[-1].text


@pytest.mark.asyncio
async def test_substring_key_resolves_then_reads():
    c = _cmd([
        (lambda a: a.get("list_sources"),
         {"sources": [{"source": "enumerate_applications:device=emu", "count": 2}]}),
        (lambda a: a.get("source") == "enumerate_applications:device=emu",
         {"store": "@snapshots", "source": "enumerate_applications:device=emu",
          "total": 2, "shown": 2, "rows": [{"identifier": "com.bank"}]}),
    ])
    msgs = await _collect(c, "applications")
    assert "com.bank" in msgs[-1].text


@pytest.mark.asyncio
async def test_ambiguous_substring_lists_candidates():
    c = _cmd([(lambda a: a.get("list_sources"),
               {"sources": [{"source": "enumerate_exports:module=libart.so", "count": 9},
                            {"source": "enumerate_exports:module=libartbase.so", "count": 3}]})])
    msgs = await _collect(c, "libart")
    text = msgs[-1].text
    assert "libart.so" in text and "libartbase.so" in text


@pytest.mark.asyncio
async def test_no_match_message():
    c = _cmd([(lambda a: a.get("list_sources"), {"sources": []})])
    msgs = await _collect(c, "nope")
    assert "no snapshot matches" in msgs[-1].text.lower()
```

- [ ] **Step 2: Run to verify it fails**

Run: `/home/edible/Projects/PARE/.venv/bin/python -m pytest tests/test_snapshot_command.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'pare.commands.snapshot'`.

- [ ] **Step 3: Implement the command**

Create `PARE/pare/commands/snapshot.py`:

```python
"""/snapshot — deterministic viewer over the frida worker's @snapshots store.

Calls the worker's page_capture tool through the audited tool_pool and renders
the rows itself; the LLM is never in this path (commands bypass the model).
"""
from __future__ import annotations

import json
from collections.abc import AsyncIterator

from agent_core.commands.base import Command
from agent_core.protocol.messages import ResponseMessage

from pare.commands._snapshot_render import render_table, render_catalog

_WORKER = "frida"
_HANDLE = "@snapshots"


def _result_text(result) -> str:
    return "".join(getattr(b, "text", "") for b in (getattr(result, "content", None) or []))


class Snapshot(Command):
    name = "snapshot"
    args = "[list | <key> [query]]"
    description = "View a captured snapshot from @snapshots (complete, deterministic)"

    async def _page(self, ctx, **args) -> dict | None:
        args.setdefault("session_id", _HANDLE)
        result = await ctx.agent.tool_pool.call_tool(_WORKER, "page_capture", args, ctx=ctx)
        if getattr(result, "isError", False):
            return None
        return json.loads(_result_text(result))

    async def run(self, raw_args: str, ctx) -> AsyncIterator:
        parts = raw_args.split(None, 1)
        sub = parts[0] if parts else ""
        rest = parts[1].strip() if len(parts) > 1 else ""

        if sub == "list":
            data = await self._page(ctx, list_sources=True)
            if data is None:
                yield ResponseMessage(text="snapshot read failed")
                return
            yield ResponseMessage(text=render_catalog(data.get("sources", [])))
            return

        if sub == "":
            data = await self._page(ctx)            # latest
            yield ResponseMessage(text=self._render(data))
            return

        # sub = key substring, rest = optional query. Resolve against the catalog.
        catalog = await self._page(ctx, list_sources=True)
        sources = [s["source"] for s in (catalog or {}).get("sources", [])]
        matches = [s for s in sources if sub in s]
        if not matches:
            yield ResponseMessage(text=f"no snapshot matches '{sub}' — try /snapshot list")
            return
        if len(matches) > 1:
            listing = "\n".join(f"  {m}" for m in matches)
            yield ResponseMessage(text=f"ambiguous key '{sub}' — matches:\n{listing}")
            return
        kwargs = {"source": matches[0]}
        if rest:
            kwargs.update(field="summary", contains=rest)
        data = await self._page(ctx, **kwargs)
        yield ResponseMessage(text=self._render(data, query=rest))

    def _render(self, data: dict | None, query: str = "") -> str:
        if data is None:
            return "snapshot read failed"
        if not data.get("source"):
            return "nothing captured yet — run an enumerate tool first"
        rows = data.get("rows", [])
        total, shown = data.get("total", len(rows)), data.get("shown", len(rows))
        if query and total == 0:
            return f"0 rows match '{query}' in {data['source']}"
        header = f"{data['source']} · {total} rows" + (
            f" (showing {shown})" if shown < total else "")
        return f"{header}\n{render_table(rows)}"
```

- [ ] **Step 4: Run to verify it passes**

Run: `/home/edible/Projects/PARE/.venv/bin/python -m pytest tests/test_snapshot_command.py -v`
Expected: PASS (5 tests).

- [ ] **Step 5: Register the command**

In `PARE/pare/agent.py`, add the import near the other command imports (line 35-36):

```python
from pare.commands.snapshot import Snapshot
```

and add `Snapshot` to the `commands` list (line 48):

```python
    commands = [Hello, Health, Snapshot]
```

- [ ] **Step 6: Verify registration import + tests**

Run: `/home/edible/Projects/PARE/.venv/bin/python -c "import pare.agent" && /home/edible/Projects/PARE/.venv/bin/python -m pytest tests/test_snapshot_command.py tests/test_register_tools.py -q`
Expected: PASS (import succeeds; command tests + existing registration test green).

- [ ] **Step 7: Commit**

```bash
git add pare/commands/snapshot.py pare/agent.py tests/test_snapshot_command.py
git commit -m "feat(snapshot): /snapshot command (latest/list/key+query) over @snapshots"
```

---

## Task 6: Discoverability — enumerate returns advertise `/snapshot`

**Files:**
- Modify: `src/pare_frida_mcp/tools.py` (`enumerate_processes`, `enumerate_applications` summary strings)
- Test: `tests/unit/test_tools_page.py` (append)

- [ ] **Step 1: Write the failing test**

Append to `tests/unit/test_tools_page.py`:

```python
@pytest.mark.asyncio
async def test_enumerate_summary_advertises_snapshot(monkeypatch):
    from pare_frida_mcp.core import devices as devices_mod
    monkeypatch.setattr(devices_mod, "get_device", lambda _id=None: type("D", (), {"id": "emu", "type": "usb"})())
    monkeypatch.setattr(devices_mod, "enumerate_processes", lambda d: [{"pid": 1, "name": "init"}])
    out = json.loads(await T.enumerate_processes("emu"))
    assert "/snapshot" in out["summary"]
```

- [ ] **Step 2: Run to verify it fails**

Run: `cd /home/edible/Projects/pare-frida-mcp && /home/edible/Projects/PARE/.venv/bin/python -m pytest tests/unit/test_tools_page.py::test_enumerate_summary_advertises_snapshot -v`
Expected: FAIL — `assert '/snapshot' in '<current summary without it>'`.

- [ ] **Step 3: Implement**

In `src/pare_frida_mcp/tools.py`, append ` Run /snapshot to view all.` to the `_ok` summary strings in `enumerate_processes` and `enumerate_applications`. For `enumerate_processes` (near line 106):

```python
        return _ok(f"{n} processes captured to @snapshots. Run /snapshot to view all, "
                   f"or search_capture(session_id='@snapshots', field='source', contains='{key}').",
                   store=SNAPSHOT_HANDLE, source=key, total=n)
```

For `enumerate_applications` (near line 123):

```python
        return _ok(f"{n} applications captured to @snapshots. Run /snapshot to view all, "
                   f"or search_capture(session_id='@snapshots', field='source', contains='{key}').",
                   store=SNAPSHOT_HANDLE, source=key, total=n)
```

- [ ] **Step 4: Run to verify it passes**

Run: `/home/edible/Projects/PARE/.venv/bin/python -m pytest tests/unit/test_tools_page.py -v`
Expected: PASS (all, including the new advertise test).

- [ ] **Step 5: Commit**

```bash
git add src/pare_frida_mcp/tools.py tests/unit/test_tools_page.py
git commit -m "feat(tools): enumerate returns advertise /snapshot"
```

---

## Final verification

- [ ] **pare-frida-mcp suite**

Run: `cd /home/edible/Projects/pare-frida-mcp && /home/edible/Projects/PARE/.venv/bin/python -m pytest tests/unit -q`
Expected: PASS. (The `test_wire_risk_tier.py::test_worker_passes_live_stdio_conformance` failure is the known pre-existing `agent_core`-import env issue — not in `tests/unit`, so this run is clean.)

- [ ] **PARE snapshot + risk suites**

Run: `cd /home/edible/Projects/PARE && /home/edible/Projects/PARE/.venv/bin/python -m pytest tests/test_snapshot_render.py tests/test_snapshot_command.py tests/test_risk_overrides_coverage.py -q`
Expected: PASS.

---

## Self-Review

- **Spec coverage:** `page_capture` complete/byte-honest read → Task 2/3; latest via MRU → Task 1; `summary`-only LIKE on own allowlist → Task 2 (`_PAGE_FIELDS`); `list_sources` catalog → Task 2/3; gated-`tool_pool` call → Task 5 (`ctx.agent.tool_pool`, audited); bare/latest, `list`, `<key> [query]`, ambiguous, no-match → Task 5; dynamic-column width-clipped render → Task 4; exempt-from-4096-cap → Task 3 (`_PAGE_BUDGET`, direct `json.dumps`); discoverability hook → Task 6; model-steer on the uncapped tool → Task 3 (description). Paging/cursor, NL trigger, `/log`, per-column search → deliberately out of scope per spec. No gaps.
- **Placeholder scan:** none — every code step has complete code; every run step has command + expected output.
- **Type consistency:** `page_rows`→`{rows,total,shown}` consumed identically in the handler (Task 3) and asserted in tests; handler return `{store,source,rows,total,shown}` / `{sources}` consumed by the command's `_page`/`_render` (Task 5) and matched by the fake `_Pool` payloads; `render_table(rows, max_width)` / `render_catalog(sources)` signatures match call sites; `latest_source()` (Task 1) used in Task 3.
