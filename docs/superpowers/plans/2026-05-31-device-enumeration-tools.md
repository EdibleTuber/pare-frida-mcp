# Device Enumeration Tools Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add device-scoped `enumerate_processes` and `enumerate_applications` tools so the agent can list running processes and installed packages without attaching to a process.

**Architecture:** Three layers following existing seams — a `page_items` byte-aware pagination helper in `bounding.py`, two pure mapping/filtering functions in `core/devices.py`, and two async handlers in `tools.py` wired into the contract. Output is paginated at the item level so the JSON is always valid under the 4096-byte tool cap.

**Tech Stack:** Python 3, frida ≥17, FastMCP, pytest / pytest-asyncio.

---

## File Structure

- `src/pare_frida_mcp/bounding.py` — **modify**: add `page_items()`.
- `src/pare_frida_mcp/core/devices.py` — **modify**: add `enumerate_processes()`, `enumerate_applications()`, `_match()`.
- `src/pare_frida_mcp/tools.py` — **modify**: add `enumerate_processes()`, `enumerate_applications()` handlers + `_page_summary()`.
- `src/pare_frida_mcp/contract.py` — **modify**: add two `ToolSpec`s; tighten descriptions of `enumerate_modules`, `enumerate_exports`, `execute_script`.
- `tests/unit/test_bounding.py` — **modify**: tests for `page_items`.
- `tests/unit/test_device_enum.py` — **create**: tests for the device-layer functions.
- `tests/unit/test_tools_enum.py` — **create**: tests for the handlers (fake device, no frida).
- `tests/device/test_android_flows.py` — **modify**: emulator-gated real-device assertions.

---

## Task 1: `page_items` pagination helper

**Files:**
- Modify: `src/pare_frida_mcp/bounding.py`
- Test: `tests/unit/test_bounding.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_bounding.py`:

```python
import json
from pare_frida_mcp.bounding import page_items


def _items(n):
    return [{"pid": i, "name": f"proc-{i}"} for i in range(n)]


def test_page_fits_returns_all_untruncated():
    page, nxt, truncated = page_items(_items(5), offset=0, limit=0, byte_budget=4096)
    assert len(page) == 5
    assert truncated is False
    assert nxt is None


def test_page_overflow_truncates_at_item_level_and_stays_valid_json():
    items = [{"pid": i, "name": "x" * 80} for i in range(500)]
    page, nxt, truncated = page_items(items, offset=0, limit=0, byte_budget=4096)
    assert truncated is True
    assert 0 < len(page) < 500
    # The whole envelope must serialize and re-parse cleanly.
    json.loads(json.dumps({"processes": page}))
    assert nxt == len(page)


def test_paging_with_offset_walks_without_gap_or_overlap():
    items = [{"pid": i, "name": "x" * 80} for i in range(500)]
    seen, offset, guard = [], 0, 0
    while offset is not None:
        page, offset, _ = page_items(items, offset=offset, limit=0, byte_budget=4096)
        seen.extend(p["pid"] for p in page)
        guard += 1
        assert guard < 1000  # forward-progress guard
    assert seen == list(range(500))


def test_explicit_limit_caps_count():
    page, nxt, truncated = page_items(_items(100), offset=0, limit=10, byte_budget=4096)
    assert len(page) == 10
    assert truncated is True
    assert nxt == 10


def test_single_oversized_item_still_advances():
    items = [{"pid": 0, "name": "z" * 9000}, {"pid": 1, "name": "ok"}]
    page, nxt, truncated = page_items(items, offset=0, limit=0, byte_budget=4096)
    assert len(page) == 1  # at least one item to guarantee progress
    assert nxt == 1
    assert truncated is True
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/unit/test_bounding.py -v`
Expected: FAIL with `ImportError: cannot import name 'page_items'`.

- [ ] **Step 3: Implement `page_items`**

Add to `src/pare_frida_mcp/bounding.py`:

```python
import json


def page_items(items, offset=0, limit=0, byte_budget=4096, reserve=512):
    """Return (page, next_offset, truncated).

    Appends items starting at `offset` until adding another would push the
    serialized list past (byte_budget - reserve), or until `limit` items are
    collected (when limit > 0). Truncation happens at the item level so the
    surrounding JSON is always structurally valid. `reserve` leaves headroom
    for the response envelope (summary/total/offset/... keys). At least one
    item per page is emitted so pagination always makes forward progress.
    next_offset is the index to resume from, or None when nothing remains.
    """
    start = max(0, offset)
    budget = max(0, byte_budget - reserve)
    page = []
    size = 2  # the enclosing [] of the list
    for item in items[start:]:
        if limit and len(page) >= limit:
            break
        item_bytes = len(json.dumps(item).encode("utf-8")) + 1  # +1 for the comma
        if page and size + item_bytes > budget:
            break
        page.append(item)
        size += item_bytes
    consumed = start + len(page)
    truncated = consumed < len(items)
    next_offset = consumed if truncated else None
    return page, next_offset, truncated
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/unit/test_bounding.py -v`
Expected: PASS (all bounding tests, old and new).

- [ ] **Step 5: Commit**

```bash
git add src/pare_frida_mcp/bounding.py tests/unit/test_bounding.py
git commit -m "feat(bounding): byte-aware page_items helper for paginated tool output"
```

---

## Task 2: Device-layer enumeration functions

**Files:**
- Modify: `src/pare_frida_mcp/core/devices.py`
- Test: `tests/unit/test_device_enum.py` (create)

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_device_enum.py`:

```python
from pare_frida_mcp.core import devices as devices_mod


class FakeProc:
    def __init__(self, pid, name):
        self.pid, self.name = pid, name


class FakeApp:
    def __init__(self, identifier, name, pid):
        self.identifier, self.name, self.pid = identifier, name, pid


class FakeDevice:
    def __init__(self, type="usb", procs=(), apps=()):
        self.type = type
        self._procs = list(procs)
        self._apps = list(apps)

    def enumerate_processes(self):
        return self._procs

    def enumerate_applications(self, scope=None):
        self.scope_used = scope
        return self._apps


def test_processes_mapped_sorted_and_filtered():
    dev = FakeDevice(procs=[FakeProc(2, "Zebra"), FakeProc(1, "alpha"), FakeProc(3, "beta")])
    res = devices_mod.enumerate_processes(dev, filter="A")  # case-insensitive substring
    names = [p["name"] for p in res]
    assert names == ["alpha", "Zebra"]  # 'beta' excluded; sorted case-insensitively
    assert res[0] == {"pid": 1, "name": "alpha"}


def test_processes_none_name_does_not_crash():
    dev = FakeDevice(procs=[FakeProc(1, None), FakeProc(2, "init")])
    res = devices_mod.enumerate_processes(dev, filter="init")
    assert [p["pid"] for p in res] == [2]


def test_applications_match_on_identifier_or_name_and_request_minimal_scope():
    dev = FakeDevice(apps=[
        FakeApp("com.example.app", "Cool App", 0),
        FakeApp("org.other.thing", "Other", 1234),
    ])
    res = devices_mod.enumerate_applications(dev, filter="example")  # matches identifier
    assert res == [{"identifier": "com.example.app", "name": "Cool App", "pid": 0}]
    assert dev.scope_used == "minimal"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/unit/test_device_enum.py -v`
Expected: FAIL with `AttributeError: module ... has no attribute 'enumerate_processes'`.

- [ ] **Step 3: Implement the functions**

Append to `src/pare_frida_mcp/core/devices.py`:

```python
def _match(value: str | None, filt: str | None) -> bool:
    if filt is None:
        return True
    return filt.lower() in (value or "").lower()


def enumerate_processes(device, filter: str | None = None) -> list[dict]:
    procs = [{"pid": p.pid, "name": p.name} for p in device.enumerate_processes()]
    procs = [p for p in procs if _match(p["name"], filter)]
    procs.sort(key=lambda p: (p["name"] or "").lower())
    return procs


def enumerate_applications(device, filter: str | None = None) -> list[dict]:
    try:
        apps = device.enumerate_applications(scope="minimal")
    except TypeError:
        # Older/alternate frida builds may not accept the scope kwarg.
        apps = device.enumerate_applications()
    out = [{"identifier": a.identifier, "name": a.name, "pid": a.pid} for a in apps]
    out = [a for a in out if _match(a["name"], filter) or _match(a["identifier"], filter)]
    out.sort(key=lambda a: (a["name"] or "").lower())
    return out
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/unit/test_device_enum.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/pare_frida_mcp/core/devices.py tests/unit/test_device_enum.py
git commit -m "feat(devices): device-scoped process/application enumeration helpers"
```

---

## Task 3: Tool handlers

**Files:**
- Modify: `src/pare_frida_mcp/tools.py`
- Test: `tests/unit/test_tools_enum.py` (create)

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_tools_enum.py`:

```python
import json
import pytest

from pare_frida_mcp import tools as T
from pare_frida_mcp.core import devices as devices_mod


class FakeProc:
    def __init__(self, pid, name):
        self.pid, self.name = pid, name


class FakeApp:
    def __init__(self, identifier, name, pid):
        self.identifier, self.name, self.pid = identifier, name, pid


class FakeDevice:
    def __init__(self, type="usb", procs=(), apps=()):
        self.type = type
        self._procs = list(procs)
        self._apps = list(apps)

    def enumerate_processes(self):
        return self._procs

    def enumerate_applications(self, scope=None):
        return self._apps


@pytest.mark.asyncio
async def test_enumerate_processes_returns_paginated_valid_json(monkeypatch):
    dev = FakeDevice(procs=[FakeProc(i, "x" * 80) for i in range(500)])
    monkeypatch.setattr(devices_mod, "get_device", lambda _id: dev)
    res = json.loads(await T.enumerate_processes(device_id="emulator-5554"))
    assert res["total"] == 500
    assert res["truncated"] is True
    assert 0 < res["returned"] < 500
    assert res["next_offset"] == res["returned"]
    assert len(res["processes"]) == res["returned"]


@pytest.mark.asyncio
async def test_enumerate_processes_offset_paging_reaches_the_tail(monkeypatch):
    dev = FakeDevice(procs=[FakeProc(i, "x" * 80) for i in range(500)])
    monkeypatch.setattr(devices_mod, "get_device", lambda _id: dev)
    seen, offset, guard = [], 0, 0
    while offset is not None:
        res = json.loads(await T.enumerate_processes(offset=offset))
        seen.extend(p["pid"] for p in res["processes"])
        offset = res["next_offset"]
        guard += 1
        assert guard < 1000
    assert sorted(seen) == list(range(500))


@pytest.mark.asyncio
async def test_enumerate_applications_local_device_short_circuits(monkeypatch):
    dev = FakeDevice(type="local")
    monkeypatch.setattr(devices_mod, "get_device", lambda _id: dev)
    res = json.loads(await T.enumerate_applications())
    assert res["applications"] == []
    assert "not supported" in res["summary"]
    assert res.get("error") is not True


@pytest.mark.asyncio
async def test_enumerate_applications_maps_fields(monkeypatch):
    dev = FakeDevice(apps=[FakeApp("com.x.y", "Y", 0)])
    monkeypatch.setattr(devices_mod, "get_device", lambda _id: dev)
    res = json.loads(await T.enumerate_applications(filter="com.x"))
    assert res["applications"] == [{"identifier": "com.x.y", "name": "Y", "pid": 0}]
    assert res["total"] == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/unit/test_tools_enum.py -v`
Expected: FAIL with `AttributeError: module 'pare_frida_mcp.tools' has no attribute 'enumerate_processes'`.

- [ ] **Step 3: Implement the handlers**

Add to `src/pare_frida_mcp/tools.py`. First add the import near the top (alongside the existing `from pare_frida_mcp.bounding import bound_text`):

```python
from pare_frida_mcp.bounding import bound_text, page_items
```

Then add the summary helper after `_err`:

```python
def _page_summary(noun: str, total: int, offset: int, page: list) -> str:
    end = offset + len(page)
    if end < total:
        return f"{total} {noun} (showing {offset}-{end} of {total}; pass offset={end} for more)"
    return f"{total} {noun} (showing {offset}-{end} of {total})"
```

Then add the two handlers (placed after `attach`, alongside the other enumerators):

```python
async def enumerate_processes(device_id: str = "", filter: str = "",
                              offset: int = 0, limit: int = 0) -> str:
    try:
        d = devices_mod.get_device(device_id or None)
        items = devices_mod.enumerate_processes(d, filter or None)
        page, nxt, trunc = page_items(items, offset, limit, _CAP)
        return _ok(_page_summary("processes", len(items), offset, page),
                   processes=page, total=len(items), offset=offset,
                   returned=len(page), truncated=trunc, next_offset=nxt)
    except Exception as e:
        return _err("enumerate_processes failed", e)


async def enumerate_applications(device_id: str = "", filter: str = "",
                                 offset: int = 0, limit: int = 0) -> str:
    try:
        d = devices_mod.get_device(device_id or None)
        if getattr(d, "type", None) == "local":
            return _ok("application enumeration not supported on device type "
                       "'local' - use enumerate_processes",
                       applications=[], total=0, offset=offset,
                       returned=0, truncated=False, next_offset=None)
        items = devices_mod.enumerate_applications(d, filter or None)
        page, nxt, trunc = page_items(items, offset, limit, _CAP)
        return _ok(_page_summary("applications", len(items), offset, page),
                   applications=page, total=len(items), offset=offset,
                   returned=len(page), truncated=trunc, next_offset=nxt)
    except Exception as e:
        return _err("enumerate_applications failed", e)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/unit/test_tools_enum.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/pare_frida_mcp/tools.py tests/unit/test_tools_enum.py
git commit -m "feat(tools): enumerate_processes/applications handlers with pagination"
```

---

## Task 4: Contract specs + description tightening

**Files:**
- Modify: `src/pare_frida_mcp/contract.py`
- Test: `tests/integration/test_server_list_tools.py` (modify), `tests/integration/test_wire_risk_tier.py` (run, no edit)

- [ ] **Step 1: Write the failing test**

In `tests/integration/test_server_list_tools.py`, extend the subset assertion to require the new tools. Replace the existing assertion block:

```python
    assert {"list_devices", "attach", "execute_script", "write_memory",
            "search_capture", "read_capture",
            "enumerate_processes", "enumerate_applications"} <= names
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/integration/test_server_list_tools.py -v`
Expected: FAIL — `enumerate_processes`/`enumerate_applications` not in `names`.

- [ ] **Step 3: Add the specs and tighten descriptions**

In `src/pare_frida_mcp/contract.py`, add these two entries to `TOOL_SPECS` (place them right after the `attach` entry):

```python
    ToolSpec("enumerate_processes", "low",
             "List processes running on a device. Device-scoped: needs no "
             "attach/session - pass device_id (or omit for the sole USB "
             "device). Use filter/offset to page large lists.",
             _in(device_id={"type": "string"}, filter={"type": "string"},
                 offset={"type": "integer"}, limit={"type": "integer"})),
    ToolSpec("enumerate_applications", "low",
             "List installed apps/packages on a device. Device-scoped: no "
             "attach needed. 'identifier' is the package name. Use "
             "filter/offset to page large lists.",
             _in(device_id={"type": "string"}, filter={"type": "string"},
                 offset={"type": "integer"}, limit={"type": "integer"})),
```

Then tighten the three existing descriptions in place:

- `enumerate_modules` description → `"List modules loaded in an ATTACHED process (requires session_id from attach)."`
- `enumerate_exports` description → `"List exports of a module in an ATTACHED process (requires session_id from attach)."`
- `execute_script` description → `"Evaluate arbitrary JS in a session (critical/last resort). For listing devices, processes, applications, modules, or exports, use the dedicated low-risk enumerate_* tools instead."`

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/integration/test_server_list_tools.py tests/integration/test_wire_risk_tier.py tests/unit/test_contract.py -v`
Expected: PASS. `test_wire_risk_tier.py` automatically confirms both new tools advertise `low` in `_meta`.

- [ ] **Step 5: Commit**

```bash
git add src/pare_frida_mcp/contract.py tests/integration/test_server_list_tools.py
git commit -m "feat(contract): register enumerate_processes/applications; clarify tool descriptions"
```

---

## Task 5: Real-device (emulator) coverage

**Files:**
- Modify: `tests/device/test_android_flows.py`

- [ ] **Step 1: Write the device tests**

Append to `tests/device/test_android_flows.py`:

```python
@pytest.mark.asyncio
async def test_enumerate_processes_on_emulator():
    res = json.loads(await T.enumerate_processes(device_id="emulator-5554", filter="system"))
    assert res["total"] >= 1, res
    assert all("pid" in p and "name" in p for p in res["processes"])
    # paginated output must always be parseable (it already json.loaded above)


@pytest.mark.asyncio
async def test_enumerate_applications_on_emulator():
    res = json.loads(await T.enumerate_applications(device_id="emulator-5554"))
    assert res["total"] >= 1, res
    ids = {a["identifier"] for a in res["applications"]}
    # The Android settings package is present on every emulator image.
    assert any("settings" in i for i in ids) or res["truncated"], res
```

- [ ] **Step 2: Run the device tests**

Run: `python3 -m pytest tests/device/test_android_flows.py -v`
Expected: PASS when `emulator-5554` is running; SKIP (via the `usb_device` fixture) otherwise. If the applications assertion proves flaky on the local image, narrow with `filter="settings"` and assert `total >= 1`.

- [ ] **Step 3: Commit**

```bash
git add tests/device/test_android_flows.py
git commit -m "test(device): emulator coverage for enumerate_processes/applications"
```

---

## Task 6: Full-suite verification

- [ ] **Step 1: Run the whole unit + integration suite**

Run: `python3 -m pytest tests/unit tests/integration -v`
Expected: PASS (device tests skip without an emulator).

- [ ] **Step 2: Confirm live stdio conformance still holds (if console script is on PATH)**

Run: `python3 -m pytest tests/integration/test_wire_risk_tier.py -v`
Expected: PASS or SKIP (skips if `pare-frida-mcp` is not on PATH).

- [ ] **Step 3: Final commit if anything is outstanding**

```bash
git status
# commit any stragglers; otherwise nothing to do
```

---

## Notes for the implementer

- **Why pagination, not the capture store:** the capture store that `execute_script` spills into is keyed by `session_id`; these tools are device-scoped and have no session, so they cannot use it. `bound_text` truncates raw bytes and would corrupt the JSON. Item-level pagination is the self-contained fix.
- **Risk tier reality:** the tools advertise `low`, but PARE floors the frida worker at `risk_default: high`, so they currently resolve to `high` (operator approval). That is expected — the win is avoiding the `critical` `execute_script` path, not skipping approval.
- **`scope='minimal'`:** controls Frida's fetch cost on Android; the `TypeError` fallback covers builds whose signature differs. Python-side field trimming does *not* reduce fetch cost.
- **Stub trap:** `server.py` substitutes a no-op `_stub` for any spec whose handler name is missing from `tools.py`. Implement Task 3 before Task 4 (this plan's order does) so registration binds the real handlers.
