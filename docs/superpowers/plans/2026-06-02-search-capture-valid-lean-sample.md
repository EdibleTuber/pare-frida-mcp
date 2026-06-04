# search_capture: valid JSON, lean rows, count preview, spread sampling — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `search_capture` preserve context economy without breaking: always-valid JSON (item-level bounding), lean rows (drop null columns), a `count_only` probe, a model-controlled `limit`, and deterministic spread sampling — so a local model can persist-then-search large snapshots reliably.

**Architecture:** A pure `fit_items` helper in `bounding.py` fits whole rows under a byte budget (the valid-JSON analogue of the removed `page_items`). `capture/search.py` is reworked to COUNT, optionally short-circuit (`count_only`), select a spread of `limit` rows when the match set is larger, lean each row, clip oversized payload/summary values, and fit under budget — returning a structured dict that is always valid. The `tools.py` handler passes the new inputs and builds prose guidance; `contract.py` exposes the two new inputs. Finally `_ok`/`_err` are hardened into a **universal valid-JSON floor**: any oversized payload returns a valid fallback envelope instead of a byte-truncated (corrupt) string — protecting every tool, not just `search_capture`.

**Tech Stack:** Python 3, SQLite/FTS5, FastMCP, pytest / pytest-asyncio.

**Spec:** `docs/superpowers/specs/2026-06-02-search-capture-valid-lean-sample-design.md`

**Test interpreter:** Use `/home/edible/Projects/PARE/.venv/bin/python -m pytest` for ALL test runs in this plan. That venv has `agent_core` (needed by integration tests via `server.py`) and `frida`. Plain `/usr/bin/python3` lacks both. Define once per shell: `PY=/home/edible/Projects/PARE/.venv/bin/python`.

---

## File Structure

- `src/pare_frida_mcp/bounding.py` — **modify**: add `fit_items(items, byte_budget, reserve=512)`.
- `src/pare_frida_mcp/capture/search.py` — **modify**: rework `search_capture` (count_only, spread sampling, lean rows, payload clipping, item-level fit, accurate total, `sampled` flag). Add module helpers `_spread`, `_lean`, `_fetch_rows`.
- `src/pare_frida_mcp/tools.py` — **modify**: `search_capture` handler gains `limit` and `count_only`; builds prose summary with narrow/sample guidance; assembles `_ok` from pre-fitted rows. Separately, harden `_ok`/`_err` to a universal valid-JSON floor (Task 5).
- `src/pare_frida_mcp/contract.py` — **modify**: add `limit` (integer) + `count_only` (boolean) to `search_capture` input_schema; update description. risk_tier stays `low`.
- `tests/unit/test_bounding.py` — **modify**: add `fit_items` tests.
- `tests/unit/test_capture_search.py` — **modify**: add lean/count_only/limit/spread/valid-JSON tests.
- `tests/unit/test_tools_search.py` — **create**: handler-level tests (count_only, limit, end-to-end valid JSON, summary guidance) via the `@snapshots` handle.
- `tests/unit/test_tools_envelope.py` — **create**: `_ok`/`_err` valid-JSON-floor tests.
- `tests/integration/test_server_list_tools.py` — no new tool name; no change needed. `tests/unit/test_contract.py` already asserts the `@snapshots` mention — keep it true.

**Ordering:** Task 1 (helper) → Task 2 (search engine) → Task 3 (handler) → Task 4 (contract) → Task 5 (`_ok`/`_err` floor) → Task 6 (full verification).

---

## Task 1: `fit_items` byte-aware item fitter

**Files:**
- Modify: `src/pare_frida_mcp/bounding.py`
- Test: `tests/unit/test_bounding.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_bounding.py`:

```python
import json
from pare_frida_mcp.bounding import fit_items


def test_fit_all_when_under_budget():
    items = [{"pid": i, "name": f"p{i}"} for i in range(5)]
    fitted, fully = fit_items(items, byte_budget=4096)
    assert fitted == items
    assert fully is True


def test_fit_drops_whole_items_and_stays_valid_json():
    items = [{"pid": i, "name": "x" * 80} for i in range(500)]
    fitted, fully = fit_items(items, byte_budget=4096)
    assert fully is False
    assert 0 < len(fitted) < 500
    json.loads(json.dumps({"matches": fitted}))  # must round-trip


def test_fit_returns_at_least_one_item():
    items = [{"blob": "z" * 9000}, {"pid": 2}]
    fitted, fully = fit_items(items, byte_budget=4096)
    assert len(fitted) == 1          # forward progress guaranteed
    assert fully is False


def test_fit_empty_is_fully_fit():
    fitted, fully = fit_items([], byte_budget=4096)
    assert fitted == []
    assert fully is True
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `PY=/home/edible/Projects/PARE/.venv/bin/python; $PY -m pytest tests/unit/test_bounding.py -v`
Expected: FAIL — `ImportError: cannot import name 'fit_items'`.

- [ ] **Step 3: Implement `fit_items`**

Add to `src/pare_frida_mcp/bounding.py` (re-add `import json` at the top — it was removed with `page_items`; `fit_items` needs it):

```python
import json


def fit_items(items, byte_budget=4096, reserve=512):
    """Return (fitted, fully_fit). Append whole items until adding another
    would push the serialized list past (byte_budget - reserve). `reserve`
    leaves headroom for the response envelope (summary/total/... keys).
    Truncation is at the item level, so the surrounding JSON is always valid.
    At least one item is returned when any exist, to guarantee forward
    progress/visibility. fully_fit is True iff every item fit.
    """
    budget = max(0, byte_budget - reserve)
    fitted = []
    size = 2  # the enclosing [] of the list
    for item in items:
        item_bytes = len(json.dumps(item).encode("utf-8")) + 1  # +1 for the comma
        if fitted and size + item_bytes > budget:
            break
        fitted.append(item)
        size += item_bytes
    return fitted, len(fitted) == len(items)
```

Place `import json` with the other top-of-file imports (after `from __future__ import annotations`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `$PY -m pytest tests/unit/test_bounding.py -v`
Expected: PASS (the 3 existing `bound_text` tests + 4 new `fit_items` tests).

- [ ] **Step 5: Commit**

```bash
git add src/pare_frida_mcp/bounding.py tests/unit/test_bounding.py
git commit -m "feat(bounding): fit_items - envelope-aware item fitter for valid-JSON output"
```
Add a blank line then:
Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>

---

## Task 2: Rework `search_capture` engine

**Files:**
- Modify: `src/pare_frida_mcp/capture/search.py`
- Test: `tests/unit/test_capture_search.py`

Background — the CURRENT `search.py` (read it first) ends with:
```python
    matches = [dict(r) for r in rows]
    blob, truncated = bound_text(json.dumps(matches), byte_budget)
    return {"total": total, "returned": len(matches), "truncated": truncated,
            "matches": json.loads(blob) if not truncated else matches[: max(1, len(matches) // 2)]}
```
That string-truncation is the corruption source. This task replaces the whole function body.

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_capture_search.py` (it already imports `CaptureStore` and `search_capture`; add `import json` at the top if not present):

```python
def _seed_n(n, name_len=8):
    store = CaptureStore.open_memory()
    for i in range(n):
        store.write({"type": "snapshot", "source": "enum:dev=A",
                     "summary": f"proc{i:04d}",
                     "payload": {"pid": i, "name": "n" * name_len}})
    return store


def test_lean_rows_drop_null_columns():
    store = _seed_n(1)
    res = search_capture(store, field="source", contains="enum:dev=A", byte_budget=4096)
    row = res["matches"][0]
    # snapshot rows have no hook/url/method/cls/ret/blob_ref — they must be absent
    for absent in ("hook", "url", "method", "cls", "ret", "blob_ref"):
        assert absent not in row, row
    # the useful columns survive
    for present in ("seq", "source", "summary", "payload"):
        assert present in row, row
    store.close()


def test_count_only_returns_total_without_rows():
    store = _seed_n(40)
    res = search_capture(store, field="source", contains="enum:dev=A",
                         count_only=True)
    assert res["total"] == 40
    assert "matches" not in res
    store.close()


def test_limit_peek_returns_few_rows_with_true_total():
    store = _seed_n(40)
    res = search_capture(store, field="source", contains="enum:dev=A", limit=2)
    assert res["total"] == 40            # accurate full count
    assert res["returned"] == 2          # only the peek
    assert res["truncated"] is True
    assert res["sampled"] is True
    store.close()


def test_spread_sampling_is_distributed_not_first_n():
    store = _seed_n(100)
    res = search_capture(store, field="source", contains="enum:dev=A", limit=5)
    assert res["total"] == 100
    assert res["returned"] == 5
    assert res["sampled"] is True
    seqs = [m["seq"] for m in res["matches"]]
    assert seqs == sorted(seqs)
    assert seqs[0] == 1 and seqs[-1] == 100      # spread includes first and last
    assert (seqs[-1] - seqs[0]) > 5              # not five consecutive rows
    store.close()


def test_small_set_returns_all_in_order_untruncated():
    store = _seed_n(3)
    res = search_capture(store, field="source", contains="enum:dev=A", limit=50)
    assert res["total"] == 3
    assert res["returned"] == 3
    assert res["truncated"] is False
    assert res["sampled"] is False
    store.close()


def test_over_budget_result_is_valid_and_marks_truncated():
    store = _seed_n(200, name_len=200)   # 200 fat rows >> 4096 bytes
    res = search_capture(store, field="source", contains="enum:dev=A", byte_budget=4096)
    assert res["total"] == 200
    assert res["returned"] < 200
    assert res["truncated"] is True
    json.loads(json.dumps({"matches": res["matches"]}))   # always valid
    store.close()


def test_single_oversized_payload_is_clipped_not_corrupting():
    store = CaptureStore.open_memory()
    store.write({"type": "snapshot", "source": "big", "summary": "huge",
                 "payload": {"data": "Q" * 9000}})
    res = search_capture(store, field="source", contains="big", byte_budget=4096)
    assert res["returned"] == 1
    assert res["truncated"] is True            # payload was clipped
    json.loads(json.dumps(res["matches"]))      # outer JSON still valid
    assert len(res["matches"][0]["payload"].encode("utf-8")) <= 4096
    store.close()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `$PY -m pytest tests/unit/test_capture_search.py -v`
Expected: FAIL — new tests fail (no `count_only`/`limit`/`sampled` behavior; lean not applied).

- [ ] **Step 3: Implement the rework**

Replace the entire contents of `src/pare_frida_mcp/capture/search.py` with:

```python
from __future__ import annotations

import json
from typing import Any

from pare_frida_mcp.bounding import bound_text, fit_items
from pare_frida_mcp.capture.store import CaptureStore

_ALLOWED_FIELDS = {"hook", "url", "method", "cls", "ret", "source", "type"}


def _spread(seqs: list[int], limit: int) -> list[int]:
    """Pick `limit` seqs evenly spaced across the ordered list (inclusive of
    first and last). Deterministic. Assumes len(seqs) > limit and limit >= 1."""
    if limit <= 1:
        return seqs[:1]
    n = len(seqs)
    return [seqs[round(i * (n - 1) / (limit - 1))] for i in range(limit)]


def _lean(row: dict, byte_budget: int) -> tuple[dict, bool]:
    """Drop null/empty columns; clip oversized payload/summary string values so
    no single row can blow the byte budget (keeps outer JSON valid). Returns
    (lean_row, clipped)."""
    out: dict[str, Any] = {}
    clipped = False
    for k, v in row.items():
        if v in (None, ""):
            continue
        if k in ("payload", "summary") and isinstance(v, str):
            v, was = bound_text(v, byte_budget)
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
    fitted, fully = fit_items(rows, byte_budget)
    returned = len(fitted)
    clipped_any = any(leaned[i][1] for i in range(returned))
    return {"total": total, "returned": returned,
            "truncated": (returned < total) or clipped_any,
            "sampled": sampled, "matches": fitted}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `$PY -m pytest tests/unit/test_capture_search.py tests/unit/test_capture_store.py tests/unit/test_snapshots.py -v`
Expected: PASS — new tests pass AND the pre-existing `test_field_predicate_uses_column` / `test_fts_text_search` still pass (lean keeps non-null `method`; totals unchanged).

- [ ] **Step 5: Commit**

```bash
git add src/pare_frida_mcp/capture/search.py tests/unit/test_capture_search.py
git commit -m "feat(search): valid-JSON item bounding, lean rows, count_only, spread sampling"
```
Add a blank line then:
Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>

---

## Task 3: Handler — expose `limit`/`count_only`, build guidance, guarantee valid JSON end-to-end

**Files:**
- Modify: `src/pare_frida_mcp/tools.py`
- Test: `tests/unit/test_tools_search.py` (create)

The CURRENT handler (read it) is:
```python
async def search_capture(session_id: str, field: str = "", contains: str = "",
                         text: str = "", byte_budget: int = 0) -> str:
    try:
        store, s = _resolve_store(session_id)
        if s is not None:
            s.flush()
        budget = byte_budget or _CAP
        res = _search_capture(store, field=field or None, contains=contains or None,
                              text=text or None, byte_budget=budget)
        return _ok(f"{res['total']} matches", **res)
    except Exception as e:
        return _err("search_capture failed", e)
```

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_tools_search.py`:

```python
import json
import pytest

from pare_frida_mcp import tools as T
from pare_frida_mcp.core.snapshots import SNAPSHOT_HANDLE


@pytest.mark.asyncio
async def test_search_count_only_returns_total_no_rows():
    T.SNAPSHOTS.replace("enum:dev=A",
                        [{"pid": i, "name": f"p{i}"} for i in range(40)])
    res = json.loads(await T.search_capture(SNAPSHOT_HANDLE, field="source",
                                            contains="enum:dev=A", count_only=True))
    assert res["total"] == 40
    assert res.get("count_only") is True
    assert "matches" not in res
    assert "count only" in res["summary"]


@pytest.mark.asyncio
async def test_search_limit_peek_summary_mentions_sample():
    T.SNAPSHOTS.replace("enum:dev=A",
                        [{"pid": i, "name": f"p{i}"} for i in range(40)])
    res = json.loads(await T.search_capture(SNAPSHOT_HANDLE, field="source",
                                            contains="enum:dev=A", limit=2))
    assert res["total"] == 40
    assert res["returned"] == 2
    assert "spread sample" in res["summary"]
    assert "read_capture" in res["summary"]


@pytest.mark.asyncio
async def test_search_large_result_is_valid_json_and_truncated():
    # Reproduces the emulator failure: a broad search over a big snapshot.
    T.SNAPSHOTS.replace("enum:dev=A",
                        [{"pid": i, "name": "x" * 60} for i in range(200)])
    raw = await T.search_capture(SNAPSHOT_HANDLE, field="source", contains="enum:dev=A")
    res = json.loads(raw)             # MUST NOT raise (the bug we are fixing)
    assert res["total"] == 200
    assert res["truncated"] is True
    assert isinstance(res["matches"], list)


@pytest.mark.asyncio
async def test_search_exact_small_result_untruncated():
    T.SNAPSHOTS.replace("enum:dev=A", [{"pid": 1, "name": "solo"}])
    res = json.loads(await T.search_capture(SNAPSHOT_HANDLE, field="source",
                                            contains="enum:dev=A"))
    assert res["total"] == 1
    assert res["truncated"] is False
    assert res["summary"] == "1 matches"
```

(The autouse `_fresh_snapshots` fixture in `tests/unit/conftest.py` rebinds `T.SNAPSHOTS` per test, so these start clean.)

- [ ] **Step 2: Run tests to verify they fail**

Run: `$PY -m pytest tests/unit/test_tools_search.py -v`
Expected: FAIL — `count_only`/`limit` are not accepted yet (TypeError) or summary lacks the new text.

- [ ] **Step 3: Implement the handler change**

In `src/pare_frida_mcp/tools.py`, replace the existing `search_capture` handler with:

```python
async def search_capture(session_id: str, field: str = "", contains: str = "",
                         text: str = "", byte_budget: int = 0,
                         limit: int = 0, count_only: bool = False) -> str:
    try:
        store, s = _resolve_store(session_id)
        if s is not None:
            s.flush()
        budget = byte_budget or _CAP
        if count_only:
            res = _search_capture(store, field=field or None, contains=contains or None,
                                  text=text or None, count_only=True)
            return _ok(f"{res['total']} matches (count only). Add text= terms to "
                       f"narrow, or search again without count_only to sample.",
                       total=res["total"], count_only=True)
        res = _search_capture(store, field=field or None, contains=contains or None,
                              text=text or None, limit=limit or 50, byte_budget=budget)
        if not res["truncated"]:
            summary = f"{res['total']} matches"
        elif res["sampled"]:
            summary = (f"{res['total']} matches - showing a {res['returned']}-row spread "
                       f"sample. Narrow with a more specific text=, or "
                       f"read_capture(seq=...) for one record.")
        else:
            summary = (f"{res['total']} matches - showing first {res['returned']} "
                       f"(output capped). Narrow with a more specific text=, or "
                       f"read_capture(seq=...) for one record.")
        return _ok(summary, **res)
    except Exception as e:
        return _err("search_capture failed", e)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `$PY -m pytest tests/unit/test_tools_search.py tests/unit/test_snapshot_routing.py -v`
Expected: PASS — new handler tests pass AND the existing snapshot-routing tests (which call `search_capture`) still pass.

- [ ] **Step 5: Commit**

```bash
git add src/pare_frida_mcp/tools.py tests/unit/test_tools_search.py
git commit -m "feat(tools): search_capture gains limit/count_only and narrow/sample guidance"
```
Add a blank line then:
Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>

---

## Task 4: Contract — expose `limit` and `count_only`

**Files:**
- Modify: `src/pare_frida_mcp/contract.py`
- Test: `tests/unit/test_contract.py` (run; no edit expected)

- [ ] **Step 1: Update the spec entry**

In `src/pare_frida_mcp/contract.py`, replace the existing `search_capture` `ToolSpec` (currently lines ~55-58) with:

```python
    ToolSpec("search_capture", "low",
             "Search captured events for a session, or device snapshots via the "
             "reserved handle '@snapshots'. Returns lean, byte-bounded matches "
             "and the true total. Use count_only=true to get just the count, "
             "limit=N to peek at a spread sample of N rows, and a more specific "
             "text= to narrow; read_capture(seq) for one full record.",
             _in(session_id={"type": "string"}, field={"type": "string"},
                 contains={"type": "string"}, text={"type": "string"},
                 byte_budget={"type": "integer"}, limit={"type": "integer"},
                 count_only={"type": "boolean"})),
```

- [ ] **Step 2: Run the contract + list-tools tests**

Run: `$PY -m pytest tests/unit/test_contract.py tests/integration/test_server_list_tools.py -v`
Expected: PASS. `test_capture_tools_document_snapshot_handle` still passes (the description still mentions `@snapshots`); the schema now advertises `limit`/`count_only`.

- [ ] **Step 3: Commit**

```bash
git add src/pare_frida_mcp/contract.py
git commit -m "feat(contract): advertise search_capture limit and count_only inputs"
```
Add a blank line then:
Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>

---

## Task 5: Universal valid-JSON floor in `_ok` / `_err`

**Files:**
- Modify: `src/pare_frida_mcp/tools.py`
- Test: `tests/unit/test_tools_envelope.py` (create)

The corruption root cause is that `_ok`/`_err` byte-truncate the serialized JSON. This task makes them return a **valid fallback envelope** when a payload exceeds `_CAP`, so NO tool — including ones not yet converted to persist-then-search (`enumerate_modules`/`exports`) — can ever hand the model unparseable output. Tools that pre-bound their output (e.g. `search_capture` after Task 3, which reserves headroom) never reach the fallback.

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_tools_envelope.py`:

```python
import json

from pare_frida_mcp import tools as T


def test_ok_normal_payload_is_unchanged():
    out = T._ok("hi", n=1, items=[1, 2, 3])
    assert json.loads(out) == {"summary": "hi", "n": 1, "items": [1, 2, 3]}


def test_ok_oversized_payload_returns_valid_fallback_json():
    huge = {"rows": [{"x": "y" * 100} for _ in range(1000)]}  # far exceeds _CAP
    out = T._ok("done", **huge)
    res = json.loads(out)               # MUST NOT raise
    assert res["truncated"] is True
    assert "error" in res
    assert len(out.encode("utf-8")) <= T._CAP


def test_err_normal_payload_is_unchanged():
    out = T._err("boom", ValueError("bad"))
    res = json.loads(out)
    assert res["error"] is True
    assert "ValueError" in res["detail"]


def test_err_oversized_detail_returns_valid_json():
    out = T._err("boom", RuntimeError("z" * 20000))
    res = json.loads(out)               # MUST NOT raise
    assert res["error"] is True
    assert len(out.encode("utf-8")) <= T._CAP
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `PY=/home/edible/Projects/PARE/.venv/bin/python; $PY -m pytest tests/unit/test_tools_envelope.py -v`
Expected: FAIL — the oversized cases currently return byte-truncated invalid JSON, so `json.loads` raises.

- [ ] **Step 3: Harden `_ok` and `_err`**

In `src/pare_frida_mcp/tools.py`, replace the existing `_ok` and `_err` with:

```python
def _ok(summary: str, **extra: Any) -> str:
    payload = {"summary": summary, **extra}
    blob = json.dumps(payload)
    if len(blob.encode("utf-8")) <= _CAP:
        return blob
    # Too large to inline. Return a VALID fallback envelope rather than a
    # byte-truncated (invalid-JSON) string. Tools that pre-bound their output
    # never reach here; this is the universal floor for those that don't.
    short, _ = bound_text(summary, 512)
    return json.dumps({
        "summary": short,
        "truncated": True,
        "error": "result too large to inline; narrow the query or use "
                 "search_capture/read_capture",
    })


def _err(summary: str, exc: BaseException | None = None) -> str:
    payload = {"summary": summary, "error": True}
    if exc is not None:
        payload["detail"] = f"{type(exc).__name__}: {exc}"
    blob = json.dumps(payload)
    if len(blob.encode("utf-8")) <= _CAP:
        return blob
    short, _ = bound_text(summary, 512)
    detail, _ = bound_text(payload.get("detail", ""), _CAP // 2)
    return json.dumps({"summary": short, "error": True, "detail": detail})
```

(`bound_text` is already imported in `tools.py`.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `$PY -m pytest tests/unit/test_tools_envelope.py -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Run the broader unit suite for regressions**

Run: `$PY -m pytest tests/unit -q`
Expected: PASS. (Existing tools return small payloads, so the fallback path is not exercised by them — behavior is unchanged for normal results.)

- [ ] **Step 6: Commit**

```bash
git add src/pare_frida_mcp/tools.py tests/unit/test_tools_envelope.py
git commit -m "feat(tools): _ok/_err never emit invalid JSON (universal fallback envelope)"
```
Add a blank line then:
Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>

---

## Task 6: Full-suite verification

- [ ] **Step 1: Run unit + integration**

Run: `PY=/home/edible/Projects/PARE/.venv/bin/python; $PY -m pytest tests/unit tests/integration -q`
Expected: PASS, except the known-environmental `test_worker_passes_live_stdio_conformance` / `test_stdio_handshake_lists_tools` failures (the global `~/.local/bin/pare-frida-mcp` console script uses system python without `agent_core`). Note them; they are not caused by this work and reproduce on prior commits.

- [ ] **Step 2: Run device tests if an emulator is connected**

Run: `$PY -m pytest tests/device -q`
Expected: PASS if `emulator-5554` is up (the enumerate-then-search device tests now exercise the fixed path); SKIP/ERROR without an emulator or frida. If up, confirm `test_enumerate_processes_on_emulator` and `test_enumerate_applications_on_emulator` pass.

Note: `test_attach_enumerate_read` exercises the still-inline `enumerate_modules` and may remain failing — but its failure mode should change from a `JSONDecodeError` (corrupt JSON) to a clean assertion or a valid "too large" envelope, because the Task 5 floor now guarantees parseable output. Its real fix is converting `enumerate_modules` to a snapshot consumer (deferred, separate effort) — do not address it here.

- [ ] **Step 3: Final status**

```bash
git status   # commit any stragglers; otherwise nothing to do
```

---

## Notes for the implementer

- **Why item-level bounding:** raw `bound_text` on a serialized list slices JSON mid-string → invalid output. `fit_items` drops whole rows; `_lean` clips oversized `payload`/`summary` *string values* (valid because a shorter string is still valid JSON). Together they guarantee the model always receives parseable JSON.
- **`total` is independent of `returned`:** it comes from `COUNT(*)`, so truncation/sampling never hides the true magnitude — the key property that lets the model trust "95 matches, showing 12."
- **Spread, not first-N:** `_spread` includes the first and last positions and evenly spaced ones between, so a `limit=N` peek shows the *variety* of the set (what the model needs to decide how to narrow), not a skewed alphabetical head.
- **Narrow-only:** there is intentionally no `offset`/paging. Guidance tells the model to narrow or `read_capture(seq)` a single record.
- **Shared store:** `_lean` drops only null/empty columns, so hook/stream rows keep their meaningful fields (`hook`/`url`/`method`/...) while snapshot rows shed them. Do not hard-code a snapshot-only projection.
- **Reserve:** `fit_items(..., reserve=512)` leaves headroom for the `_ok` envelope (summary + total + returned + truncated + sampled). The handler passes the full `byte_budget` to the engine; because of the reserve, the final `_ok` payload stays under `_CAP` and `bound_text` never fires.
- **Test interpreter:** always `/home/edible/Projects/PARE/.venv/bin/python` — it has `agent_core` + `frida`.
- **Known pre-existing gotcha (out of scope):** raw `text=` is passed to FTS5 `MATCH`, so dotted package names / hyphenated device IDs raise (`fts5: syntax error near "."`, `no such column: 5554`). This rework does not change that behavior. The deterministic retrieval path is `field="source", contains=...` (plain `LIKE`), which the enumerate tools' summaries already steer toward. Making `text=` auto-phrase-quote is a separate small follow-up — do not fold it in here.
