# Enumeration Tools (Snapshot-Store Consumer) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add device-scoped `enumerate_processes` and `enumerate_applications` tools that persist the full device list into the `@snapshots` store and return only a handle + source key, so a local model retrieves results via `search_capture` instead of consuming them inline.

**Architecture:** Two pure map/sort functions in `core/devices.py`; two thin async handlers in `tools.py` that call `SNAPSHOTS.replace(snapshot_key(...), items)` and return `{summary, store, source, total}`; two `ToolSpec`s in `contract.py` plus description tightening on the existing enumerators and `execute_script`. The now-dead `page_items` helper (built for the abandoned inline-pagination approach) is removed.

**Tech Stack:** Python 3, frida ≥17, FastMCP, pytest / pytest-asyncio.

**Spec:** `docs/superpowers/specs/2026-06-01-enumeration-snapshot-consumer-design.md`

---

## File Structure

- `src/pare_frida_mcp/core/devices.py` — **modify**: add `enumerate_processes(device)`, `enumerate_applications(device)` (pure map + case-insensitive sort, `None`-name guard).
- `src/pare_frida_mcp/tools.py` — **modify**: import `snapshot_key`; add `enumerate_processes`/`enumerate_applications` handlers.
- `src/pare_frida_mcp/contract.py` — **modify**: add two `ToolSpec`s; tighten `enumerate_modules`, `enumerate_exports`, `execute_script` descriptions.
- `src/pare_frida_mcp/bounding.py` — **modify**: remove `page_items` and its now-unused `import json`.
- `tests/unit/test_device_enum.py` — **create**: device-layer function tests (fake device, no frida).
- `tests/unit/test_tools_enum.py` — **create**: handler tests incl. end-to-end persist-then-search round-trip.
- `tests/unit/test_bounding.py` — **modify**: delete the `page_items` tests.
- `tests/integration/test_server_list_tools.py` — **modify**: extend the subset assertion.
- `tests/device/test_android_flows.py` — **modify**: emulator-gated enumerate-then-search.

**Important ordering:** implement the handlers (Task 2) **before** registering the specs (Task 3). `server.py` substitutes a no-op `_stub` for any spec whose handler name is missing from `tools.py`, which would pass conformance but break real calls.

**Test infra already in place:** `tests/unit/conftest.py` injects a frida stub at import time and has an **autouse** `_fresh_snapshots` fixture that rebinds `tools.SNAPSHOTS` to a clean `SnapshotStore()` per test — so handler tests start with an empty snapshot store automatically and monkeypatch `devices_mod.get_device` for device behavior.

---

## Task 1: Device-layer enumeration functions

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
        self.id = "emulator-5554"
        self._procs = list(procs)
        self._apps = list(apps)
        self.scope_used = "UNSET"

    def enumerate_processes(self):
        return self._procs

    def enumerate_applications(self, scope=None):
        self.scope_used = scope
        return self._apps


def test_processes_mapped_and_sorted_case_insensitively():
    dev = FakeDevice(procs=[FakeProc(2, "Zebra"), FakeProc(1, "alpha"), FakeProc(3, "Beta")])
    res = devices_mod.enumerate_processes(dev)
    assert [p["name"] for p in res] == ["alpha", "Beta", "Zebra"]
    assert res[0] == {"pid": 1, "name": "alpha"}


def test_processes_none_name_does_not_crash():
    dev = FakeDevice(procs=[FakeProc(1, None), FakeProc(2, "init")])
    res = devices_mod.enumerate_processes(dev)  # None name must not raise on sort
    assert {p["pid"] for p in res} == {1, 2}


def test_applications_mapped_sorted_by_identifier_and_request_minimal_scope():
    dev = FakeDevice(apps=[
        FakeApp("org.other.thing", "Other", 1234),
        FakeApp("com.example.app", "Cool App", 0),
    ])
    res = devices_mod.enumerate_applications(dev)
    assert [a["identifier"] for a in res] == ["com.example.app", "org.other.thing"]
    assert res[0] == {"identifier": "com.example.app", "name": "Cool App", "pid": 0}
    assert dev.scope_used == "minimal"  # scope kwarg drives Frida fetch cost
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/unit/test_device_enum.py -v`
Expected: FAIL — `AttributeError: module 'pare_frida_mcp.core.devices' has no attribute 'enumerate_processes'`.

- [ ] **Step 3: Implement the functions**

Append to `src/pare_frida_mcp/core/devices.py`:

```python
def enumerate_processes(device) -> list[dict]:
    procs = [{"pid": p.pid, "name": p.name} for p in device.enumerate_processes()]
    procs.sort(key=lambda p: (p["name"] or "").lower())
    return procs


def enumerate_applications(device) -> list[dict]:
    try:
        apps = device.enumerate_applications(scope="minimal")
    except TypeError:
        # Older/alternate frida builds may not accept the scope kwarg.
        apps = device.enumerate_applications()
    out = [{"identifier": a.identifier, "name": a.name, "pid": a.pid} for a in apps]
    out.sort(key=lambda a: (a["identifier"] or "").lower())
    return out
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/unit/test_device_enum.py -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```bash
git add src/pare_frida_mcp/core/devices.py tests/unit/test_device_enum.py
git commit -m "feat(devices): device-scoped process/application enumeration helpers"
```

---

## Task 2: Tool handlers (persist to @snapshots, return handle)

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
from pare_frida_mcp.core.snapshots import SNAPSHOT_HANDLE


class FakeProc:
    def __init__(self, pid, name):
        self.pid, self.name = pid, name


class FakeApp:
    def __init__(self, identifier, name, pid):
        self.identifier, self.name, self.pid = identifier, name, pid


class FakeDevice:
    def __init__(self, type="usb", id="emulator-5554", procs=(), apps=()):
        self.type, self.id = type, id
        self._procs, self._apps = list(procs), list(apps)

    def enumerate_processes(self):
        return self._procs

    def enumerate_applications(self, scope=None):
        return self._apps


@pytest.mark.asyncio
async def test_enumerate_processes_persists_and_returns_handle(monkeypatch):
    dev = FakeDevice(procs=[FakeProc(1, "zygote"), FakeProc(2, "system_server")])
    monkeypatch.setattr(devices_mod, "get_device", lambda _id: dev)
    res = json.loads(await T.enumerate_processes(device_id="emulator-5554"))
    assert res["store"] == SNAPSHOT_HANDLE
    assert res["total"] == 2
    assert res["source"] == "enumerate_processes:device=emulator-5554"
    assert res.get("error") is not True
    # Persist-then-search round-trip: the rows actually landed in the store.
    found = json.loads(await T.search_capture(SNAPSHOT_HANDLE, field="source",
                                              contains=res["source"]))
    assert found["total"] == 2


@pytest.mark.asyncio
async def test_enumerate_processes_replace_semantics(monkeypatch):
    dev = FakeDevice(procs=[FakeProc(1, "old_a"), FakeProc(2, "old_b")])
    monkeypatch.setattr(devices_mod, "get_device", lambda _id: dev)
    await T.enumerate_processes(device_id="emulator-5554")
    dev._procs = [FakeProc(9, "fresh_only")]  # device state changed
    res = json.loads(await T.enumerate_processes(device_id="emulator-5554"))
    found = json.loads(await T.search_capture(SNAPSHOT_HANDLE, field="source",
                                              contains=res["source"]))
    names = {m["summary"] for m in found["matches"]}
    assert names == {"fresh_only"}  # stale rows replaced, not appended


@pytest.mark.asyncio
async def test_enumerate_key_normalizes_on_resolved_device_id(monkeypatch):
    dev = FakeDevice(id="emulator-5554", procs=[FakeProc(1, "p")])
    monkeypatch.setattr(devices_mod, "get_device", lambda _id: dev)
    omitted = json.loads(await T.enumerate_processes())
    explicit = json.loads(await T.enumerate_processes(device_id="emulator-5554"))
    assert omitted["source"] == explicit["source"]  # one snapshot, not two


@pytest.mark.asyncio
async def test_enumerate_applications_uses_identifier_as_glance_value(monkeypatch):
    dev = FakeDevice(apps=[FakeApp("com.x.y", "Y App", 0)])
    monkeypatch.setattr(devices_mod, "get_device", lambda _id: dev)
    res = json.loads(await T.enumerate_applications(device_id="emulator-5554"))
    assert res["source"] == "enumerate_applications:device=emulator-5554"
    found = json.loads(await T.search_capture(SNAPSHOT_HANDLE, field="source",
                                              contains=res["source"]))
    assert found["matches"][0]["summary"] == "com.x.y"  # identifier, not display name


@pytest.mark.asyncio
async def test_enumerate_applications_local_device_short_circuits(monkeypatch):
    dev = FakeDevice(type="local", id="local")
    monkeypatch.setattr(devices_mod, "get_device", lambda _id: dev)
    res = json.loads(await T.enumerate_applications())
    assert res["total"] == 0
    assert "not supported" in res["summary"]
    assert res.get("error") is not True  # actionable _ok, not a failure
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/unit/test_tools_enum.py -v`
Expected: FAIL — `AttributeError: module 'pare_frida_mcp.tools' has no attribute 'enumerate_processes'`.

- [ ] **Step 3: Add the `snapshot_key` import**

In `src/pare_frida_mcp/tools.py`, the existing line 16 reads:

```python
from pare_frida_mcp.core.snapshots import SnapshotStore, SNAPSHOT_HANDLE
```

Replace it with:

```python
from pare_frida_mcp.core.snapshots import SnapshotStore, SNAPSHOT_HANDLE, snapshot_key
```

- [ ] **Step 4: Implement the handlers**

Add to `src/pare_frida_mcp/tools.py`, placed after the `attach` handler alongside the other enumerators:

```python
async def enumerate_processes(device_id: str = "") -> str:
    try:
        d = devices_mod.get_device(device_id or None)
        items = devices_mod.enumerate_processes(d)
        key = snapshot_key("enumerate_processes", device=getattr(d, "id", "") or "")
        n = SNAPSHOTS.replace(key, items, summary_field="name")
        return _ok(f"{n} processes captured to @snapshots. Read with "
                   f"search_capture(session_id='@snapshots', field='source', contains='{key}').",
                   store=SNAPSHOT_HANDLE, source=key, total=n)
    except Exception as e:
        return _err("enumerate_processes failed", e)


async def enumerate_applications(device_id: str = "") -> str:
    try:
        d = devices_mod.get_device(device_id or None)
        if getattr(d, "type", None) == "local":
            return _ok("application enumeration not supported on device type "
                       "'local' - use enumerate_processes",
                       store=SNAPSHOT_HANDLE, source=None, total=0)
        items = devices_mod.enumerate_applications(d)
        key = snapshot_key("enumerate_applications", device=getattr(d, "id", "") or "")
        n = SNAPSHOTS.replace(key, items, summary_field="identifier")
        return _ok(f"{n} applications captured to @snapshots. Read with "
                   f"search_capture(session_id='@snapshots', field='source', contains='{key}').",
                   store=SNAPSHOT_HANDLE, source=key, total=n)
    except Exception as e:
        return _err("enumerate_applications failed", e)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `python3 -m pytest tests/unit/test_tools_enum.py -v`
Expected: PASS (5 tests).

- [ ] **Step 6: Commit**

```bash
git add src/pare_frida_mcp/tools.py tests/unit/test_tools_enum.py
git commit -m "feat(tools): enumerate_processes/applications persist to @snapshots"
```

---

## Task 3: Contract specs + description tightening

**Files:**
- Modify: `src/pare_frida_mcp/contract.py`
- Test: `tests/integration/test_server_list_tools.py` (modify); `tests/integration/test_wire_risk_tier.py` (run, no edit)

- [ ] **Step 1: Update the failing assertion**

In `tests/integration/test_server_list_tools.py`, the existing block (lines 10-11) reads:

```python
    assert {"list_devices", "attach", "execute_script", "write_memory",
            "search_capture", "read_capture"} <= names
```

Replace it with:

```python
    assert {"list_devices", "attach", "execute_script", "write_memory",
            "search_capture", "read_capture",
            "enumerate_processes", "enumerate_applications"} <= names
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/integration/test_server_list_tools.py -v`
Expected: FAIL — `enumerate_processes`/`enumerate_applications` not in `names`.

- [ ] **Step 3: Add the specs and tighten descriptions**

In `src/pare_frida_mcp/contract.py`, add these two entries to `TOOL_SPECS`, immediately after the `attach` entry (after line 34):

```python
    ToolSpec("enumerate_processes", "low",
             "List processes running on a device into the @snapshots store. "
             "Device-scoped: needs no attach/session - pass device_id (or omit "
             "for the sole USB device). Returns a source key; read results with "
             "search_capture(session_id='@snapshots', field='source', contains=<key>).",
             _in(device_id={"type": "string"})),
    ToolSpec("enumerate_applications", "low",
             "List installed apps/packages on a device into the @snapshots store. "
             "Device-scoped: no attach needed. 'identifier' is the package name. "
             "Returns a source key; read with search_capture(session_id='@snapshots', "
             "field='source', contains=<key>).",
             _in(device_id={"type": "string"})),
```

Then change the three existing descriptions in place:

- `enumerate_modules` (line 35) description string → `"List modules loaded in an ATTACHED process (requires session_id from attach)."`
- `enumerate_exports` (line 37) description string → `"List exports of a module in an ATTACHED process (requires session_id from attach)."`
- `execute_script` (line 41) description string → `"Evaluate arbitrary JS in a session (critical/last resort). For listing devices, processes, applications, modules, or exports, use the dedicated low-risk enumerate_* tools instead."`

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/integration/test_server_list_tools.py tests/integration/test_wire_risk_tier.py tests/unit/test_contract.py -v`
Expected: PASS. `test_wire_risk_tier.py` automatically confirms both new tools advertise `low` (it may SKIP if `pare-frida-mcp` is not on PATH — that is acceptable).

- [ ] **Step 5: Commit**

```bash
git add src/pare_frida_mcp/contract.py tests/integration/test_server_list_tools.py
git commit -m "feat(contract): register enumerate_processes/applications; redirect execute_script"
```

---

## Task 4: Remove the dead `page_items` helper

**Files:**
- Modify: `src/pare_frida_mcp/bounding.py`
- Test: `tests/unit/test_bounding.py`

Rationale: `page_items` served the abandoned inline-pagination approach. Nothing in production references it (verified: only its own tests do), and `read_capture` does its own paging. Remove it.

- [ ] **Step 1: Delete the `page_items` tests**

In `tests/unit/test_bounding.py`, delete everything from line 22 (`import json`) through the end of the file, leaving only the three `bound_text` tests (lines 1-19). The file should end after `test_never_splits_codepoint`.

- [ ] **Step 2: Delete the function and its unused import**

In `src/pare_frida_mcp/bounding.py`:
- Delete the entire `def page_items(...)` function (lines 18-44).
- Delete `import json` (line 3) — it is used only by `page_items`; `bound_text` uses byte encode/decode only.

The file should contain only the `from __future__ import annotations` line and `bound_text`.

- [ ] **Step 3: Run tests to verify the suite is still green**

Run: `python3 -m pytest tests/unit/test_bounding.py -v`
Expected: PASS (3 `bound_text` tests; no import errors).

- [ ] **Step 4: Commit**

```bash
git add src/pare_frida_mcp/bounding.py tests/unit/test_bounding.py
git commit -m "refactor(bounding): drop unused page_items (inline-pagination approach abandoned)"
```

---

## Task 5: Real-device (emulator) coverage

**Files:**
- Modify: `tests/device/test_android_flows.py`

- [ ] **Step 1: Write the device tests**

Append to `tests/device/test_android_flows.py` (follows the existing emulator-gated style in that file — confirm the module already imports `json`, `pytest`, and `tools as T`; reuse those imports rather than re-adding them):

```python
@pytest.mark.asyncio
async def test_enumerate_processes_on_emulator():
    res = json.loads(await T.enumerate_processes(device_id="emulator-5554"))
    assert res["total"] >= 1, res
    found = json.loads(await T.search_capture("@snapshots", field="source",
                                              contains=res["source"]))
    assert found["total"] >= 1, found
    assert all("pid" in m["payload"] for m in found["matches"])


@pytest.mark.asyncio
async def test_enumerate_applications_on_emulator():
    res = json.loads(await T.enumerate_applications(device_id="emulator-5554"))
    assert res["total"] >= 1, res
    # The Android settings package is present on every emulator image.
    found = json.loads(await T.search_capture("@snapshots", text="settings"))
    assert found["total"] >= 1, found
```

Note: `m["payload"]` is a JSON string column; if an assertion needs the dict, `json.loads(m["payload"])`. The `"pid" in m["payload"]` substring check above holds without parsing because the key name appears in the serialized JSON.

- [ ] **Step 2: Run the device tests**

Run: `python3 -m pytest tests/device/test_android_flows.py -v`
Expected: PASS when `emulator-5554` is running; SKIP otherwise (per the suite's existing device gating). If the `text="settings"` search proves flaky on the local image, fall back to `field="source", contains=res["source"]` and assert `found["total"] >= 1`.

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

- [ ] **Step 2: Confirm live stdio risk-tier conformance**

Run: `python3 -m pytest tests/integration/test_wire_risk_tier.py -v`
Expected: PASS or SKIP (skips if `pare-frida-mcp` is not on PATH).

- [ ] **Step 3: Final status check**

```bash
git status
# commit any stragglers; otherwise nothing to do
```

---

## Notes for the implementer

- **Why no inline list:** strict persist-then-search. A local model drives PARE; the handler returns only `{summary, store, source, total}` and the model reads results with `search_capture`/`read_capture` against `@snapshots`. The summary string embeds the exact retrieval call.
- **Deterministic retrieval path:** `field="source", contains=<key>` is a plain SQL `LIKE` — no FTS tokenizer, so dotted package names match reliably. `text=` (FTS over `summary`+`payload`) is the fuzzy fallback.
- **Key normalization:** key on the resolved `device.id`, which shares the namespace of the `device_id` input, so omitted vs. explicit collapse to one snapshot. `getattr(d, "id", "") or ""` degrades safely.
- **`scope='minimal'`:** controls Frida's fetch cost on Android; the `TypeError` fallback covers builds whose signature differs. Verify the exact kwarg against the installed frida ≥17.
- **Stub trap:** `server.py` substitutes a no-op `_stub` for any spec whose handler name is missing from `tools.py`. Task 2 (handlers) precedes Task 3 (specs) for this reason.
- **Risk tier reality:** the tools advertise `low`, but PARE floors the frida worker at `risk_default: high`, so they currently resolve to `high` (operator approval). Expected — the win is avoiding the `critical` `execute_script` path, not skipping approval.
- **Snapshot test isolation:** `tests/unit/conftest.py` rebinds `tools.SNAPSHOTS` per test (autouse `_fresh_snapshots`), so handler tests start clean automatically.
