# Hook Event Capture Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `java_hook` capture decoded args + return values and surface them through a non-destructive, cursor-based `read_hook_events` tool.

**Architecture:** The bundled Frida agent (`agent/src/index.ts`) emits one flat, marked event per hook firing (decoded args/ret, per-session monotonic `seq`). `Session` retains those events in a bounded ring buffer; `SessionManager.read_events` serves them by a `since_seq` cursor (idempotent). `read_hook_events` (tier `low`) wraps that read. All new Python logic is unit-tested with fakes; the agent TypeScript is verified by a live KeyStore acceptance run.

**Tech Stack:** Python 3.12 (asyncio, pytest, pytest-asyncio), TypeScript compiled with `frida-compile`, frida-java-bridge (Frida 17).

## Global Constraints

- Frida 17 / frida-java-bridge; a bare `execute_script` has NO Java bridge — all Java work runs on the bundled-agent rpc path.
- `byte[]` in frida-java-bridge is an **array-like object**: `Array.isArray` false, `$className` undefined, numeric `length`, **signed** numeric elements. Decode predicate = "object, `$className` undefined, numeric `length`, numeric elements"; utf8 must mask `& 0xff`. (Verified live.)
- Session-scoped tools take `session_id` **last** with default `""` and resolve via `_resolve_session` (active-session fallback).
- Tool output envelope: `{"summary": ..., <fields>}` via `_ok`; errors via `_err`. The host bounds oversized results at the wire (store-and-ref `read_capture`), so the worker never truncates.
- Risk tiers: `read_hook_events` = `low`; `java_hook` stays `high`; `execute_script` stays `critical`.
- Tool count goes 17 → 18. `CONTRACT_VERSION` stays `1` (additive).
- Decode `CAP = 4096` applied to **every** `describe()` path. `read_hook_events` byte budget `_EVENT_WIRE_BUDGET` is set **below** the host `max_tool_bytes`.
- Rebuild the agent bundle with `npm run build` in `agent/` after any `index.ts` change.
- Run the unit suite with: `PYTHONPATH=src <venv>/bin/python -m pytest tests/unit -q` (conftest stubs `frida`).

---

### Task 1: Session retained event buffer + hook-marker filtering

**Files:**
- Modify: `src/pare_frida_mcp/core/sessions.py` (class `Session`, `SessionManager.__init__`, `register_session`)
- Test: `tests/unit/test_sessions_pump.py` (rewrite to the new model)

**Interfaces:**
- Consumes: the agent event shape `{hook:true, seq:int, class, method, overload, args, ret, threw, thread}` (Frida delivers it as `message={"type":"send","payload":<event>}`).
- Produces: `Session._events: deque[dict]` (ring, ascending `seq`), `Session._diagnostics: deque[dict]`, `Session.flush()`; `SessionManager(config, event_bound=2048)`, `register_session(*, script, pid, name, device_id=None)`.

- [ ] **Step 1: Write the failing test**

Replace the contents of `tests/unit/test_sessions_pump.py`:

```python
from pare_frida_mcp.config import Config
from pare_frida_mcp.core.sessions import SessionManager


class FakeScript:
    def __init__(self):
        self._cb = None
    def on(self, event, cb):
        self._cb = cb
    def emit(self, message):
        self._cb(message, None)


def _cfg(tmp_path):
    return Config(capture_dir=tmp_path, max_tool_bytes=4096,
                  blob_threshold=65536, max_disk_per_session=10**9)


def _hook_evt(seq, method="encryptString"):
    return {"type": "send", "payload": {
        "hook": True, "seq": seq, "class": "C", "method": method,
        "overload": ["[B"], "args": [{"utf8": "hi", "hex": "6869"}],
        "ret": None, "threw": False, "thread": 1}}


def test_hook_events_are_retained(tmp_path):
    mgr = SessionManager(_cfg(tmp_path))
    script = FakeScript()
    sid = mgr.register_session(script=script, pid=1, name="x")
    script.emit(_hook_evt(1))
    script.emit(_hook_evt(2))
    assert [e["seq"] for e in mgr.get(sid)._events] == [1, 2]
    mgr.close_all()


def test_non_hook_messages_are_segregated(tmp_path):
    mgr = SessionManager(_cfg(tmp_path))
    script = FakeScript()
    sid = mgr.register_session(script=script, pid=1, name="x")
    script.emit({"type": "send", "payload": {"noise": 1}})   # non-hook send
    script.emit({"type": "error", "description": "boom"})      # frida error
    s = mgr.get(sid)
    assert list(s._events) == []
    assert len(s._diagnostics) == 2
    mgr.close_all()


def test_ring_buffer_evicts_oldest(tmp_path):
    mgr = SessionManager(_cfg(tmp_path), event_bound=3)
    script = FakeScript()
    sid = mgr.register_session(script=script, pid=1, name="x")
    for n in range(1, 6):
        script.emit(_hook_evt(n))
    assert [e["seq"] for e in mgr.get(sid)._events] == [3, 4, 5]
    mgr.close_all()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src <venv>/bin/python -m pytest tests/unit/test_sessions_pump.py -q`
Expected: FAIL (e.g. `TypeError: __init__() got an unexpected keyword argument 'event_bound'` / attribute `_events` missing).

- [ ] **Step 3: Rewrite `Session` and `SessionManager` construction**

In `src/pare_frida_mcp/core/sessions.py`, replace the `Session` class and the `SessionManager.__init__` / `register_session` head:

```python
from __future__ import annotations

import json
from collections import deque
from dataclasses import dataclass
from typing import Any

from pare_frida_mcp.config import Config
from pare_frida_mcp.ids import new_session_id

_DIAGNOSTIC_BOUND = 256


class Session:
    def __init__(self, session_id: str, script: Any, pid: int, name: str,
                 event_bound: int, device_id: str | None = None):
        self.id = session_id
        self.script = script
        self.pid = pid
        self.name = name
        self.device_id = device_id
        self._events: deque[dict] = deque(maxlen=event_bound)          # hook events, seq-ascending
        self._diagnostics: deque[dict] = deque(maxlen=_DIAGNOSTIC_BOUND)  # frida errors/logs/non-hook
        self.frida_session = None
        script.on("message", self._on_message)

    def _on_message(self, message: dict, data: Any) -> None:
        if message.get("type") == "send":
            payload = message.get("payload")
            if isinstance(payload, dict) and payload.get("hook"):
                self._events.append(payload)
                return
        self._diagnostics.append(message)

    def flush(self) -> None:
        self._events.clear()
        self._diagnostics.clear()


class SessionManager:
    def __init__(self, config: Config, event_bound: int = 2048):
        # event_bound sized for enriched events (each up to ~CAP bytes hex + utf8);
        # worst-case resident memory ~= event_bound * per-event-max. NOT the old
        # 10000 thin-message default.
        self._config = config
        self._event_bound = event_bound
        self._sessions: dict[str, Session] = {}

    def register_session(self, *, script: Any, pid: int, name: str,
                         device_id: str | None = None) -> str:
        sid = new_session_id()
        self._sessions[sid] = Session(sid, script, pid, name, self._event_bound,
                                      device_id)
        return sid
```

Then delete the now-dead `flush(self, session_id)` duplicate only if it conflicts; keep `SessionManager.flush(session_id)`, `get`, `active_session`, `find_live_session`, `list_sessions`, `detach`, `close_all` as they are. Remove `dropped_count` and any `self.dropped` references (drop accounting is now read-derived in Task 2).

- [ ] **Step 4: Run tests to verify they pass**

Run: `PYTHONPATH=src <venv>/bin/python -m pytest tests/unit/test_sessions_pump.py -q`
Expected: PASS (3 passed).

- [ ] **Step 5: Run the full suite to catch fallout**

Run: `PYTHONPATH=src <venv>/bin/python -m pytest tests/unit -q`
Expected: PASS. If `test_tools_sessions.py` referenced `dropped_count`, update those references to remove them (they test `list_sessions`/`detach`, which are unchanged).

- [ ] **Step 6: Commit**

```bash
git add src/pare_frida_mcp/core/sessions.py tests/unit/test_sessions_pump.py
git commit -m "feat(sessions): retain hook events in a ring buffer, segregate diagnostics"
```

---

### Task 2: `SessionManager.read_events` + `ReadResult`

**Files:**
- Modify: `src/pare_frida_mcp/core/sessions.py` (add `ReadResult`, `read_events`)
- Test: `tests/unit/test_read_events.py` (create)

**Interfaces:**
- Consumes: `Session._events` (Task 1).
- Produces: `@dataclass ReadResult(events: list[dict], next_seq: int, buffered_remaining: int, has_more: bool, lost: int)` and `SessionManager.read_events(session_id: str, since_seq: int, limit: int, max_bytes: int) -> ReadResult`.

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_read_events.py`:

```python
from pare_frida_mcp.config import Config
from pare_frida_mcp.core.sessions import SessionManager


class FakeScript:
    def on(self, event, cb): self._cb = cb


def _mgr(tmp_path, event_bound=2048):
    cfg = Config(capture_dir=tmp_path, max_tool_bytes=4096,
                 blob_threshold=65536, max_disk_per_session=10**9)
    return SessionManager(cfg, event_bound=event_bound)


def _fill(mgr, n, event_bound=2048):
    sid = mgr.register_session(script=FakeScript(), pid=1, name="x")
    for seq in range(1, n + 1):
        mgr.get(sid)._events.append({"seq": seq, "class": "C", "method": "m"})
    return sid


def test_since_seq_selects_newer_events(tmp_path):
    mgr = _mgr(tmp_path); sid = _fill(mgr, 5)
    r = mgr.read_events(sid, since_seq=2, limit=100, max_bytes=10**6)
    assert [e["seq"] for e in r.events] == [3, 4, 5]
    assert r.next_seq == 5 and r.buffered_remaining == 0 and r.has_more is False
    assert r.lost == 0


def test_limit_paginates_and_reports_more(tmp_path):
    mgr = _mgr(tmp_path); sid = _fill(mgr, 5)
    r = mgr.read_events(sid, since_seq=0, limit=2, max_bytes=10**6)
    assert [e["seq"] for e in r.events] == [1, 2]
    assert r.next_seq == 2 and r.buffered_remaining == 3 and r.has_more is True
    assert r.lost == 0


def test_max_bytes_bounds_but_always_returns_one(tmp_path):
    mgr = _mgr(tmp_path); sid = _fill(mgr, 5)
    r = mgr.read_events(sid, since_seq=0, limit=100, max_bytes=1)
    assert len(r.events) == 1 and r.has_more is True


def test_lost_reported_when_cursor_fell_behind_eviction(tmp_path):
    # ring holds only the last 3 (seq 3,4,5); a cursor at 0 missed seq 1,2
    mgr = _mgr(tmp_path, event_bound=3); sid = _fill(mgr, 5, event_bound=3)
    r = mgr.read_events(sid, since_seq=0, limit=100, max_bytes=10**6)
    assert [e["seq"] for e in r.events] == [3, 4, 5]
    assert r.lost == 2   # seq 1 and 2 evicted before the cursor could read them


def test_caught_up_cursor_returns_empty_no_loss(tmp_path):
    mgr = _mgr(tmp_path); sid = _fill(mgr, 3)
    r = mgr.read_events(sid, since_seq=3, limit=100, max_bytes=10**6)
    assert r.events == [] and r.next_seq == 3 and r.has_more is False and r.lost == 0
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src <venv>/bin/python -m pytest tests/unit/test_read_events.py -q`
Expected: FAIL (`AttributeError: 'SessionManager' object has no attribute 'read_events'`).

- [ ] **Step 3: Implement `ReadResult` and `read_events`**

Add to `src/pare_frida_mcp/core/sessions.py` (dataclass near the top, method on `SessionManager`):

```python
@dataclass
class ReadResult:
    events: list[dict]
    next_seq: int
    buffered_remaining: int
    has_more: bool
    lost: int
```

```python
    def read_events(self, session_id: str, since_seq: int, limit: int,
                    max_bytes: int) -> ReadResult:
        """Non-destructive cursor read of hook events with seq > since_seq.

        Idempotent: reading never evicts. Stops at whichever bound (limit or
        max_bytes) is hit first, always returning at least one event when any
        qualify. `lost` counts events evicted below the cursor (the ring moved
        past since_seq) - the only true-loss signal, derived here race-free.
        """
        buf = list(self._sessions[session_id]._events)   # seq-ascending
        lost = 0
        if buf and since_seq < buf[0]["seq"] - 1:
            lost = buf[0]["seq"] - 1 - since_seq
        candidates = [e for e in buf if e["seq"] > since_seq]
        selected: list[dict] = []
        size = 0
        for e in candidates:
            if len(selected) >= limit:
                break
            esize = len(json.dumps(e))
            if selected and size + esize > max_bytes:
                break
            selected.append(e)
            size += esize
        next_seq = selected[-1]["seq"] if selected else since_seq
        remaining = len(candidates) - len(selected)
        return ReadResult(events=selected, next_seq=next_seq,
                          buffered_remaining=remaining, has_more=remaining > 0,
                          lost=lost)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `PYTHONPATH=src <venv>/bin/python -m pytest tests/unit/test_read_events.py -q`
Expected: PASS (5 passed).

- [ ] **Step 5: Commit**

```bash
git add src/pare_frida_mcp/core/sessions.py tests/unit/test_read_events.py
git commit -m "feat(sessions): read_events cursor with limit/byte bounds and lost accounting"
```

---

### Task 3: `read_hook_events` tool + contract entry

**Files:**
- Modify: `src/pare_frida_mcp/tools.py` (constants, `_clamp`, `read_hook_events`)
- Modify: `src/pare_frida_mcp/contract.py` (new `ToolSpec`; bump `test_tool_count`)
- Test: `tests/unit/test_read_hook_events.py` (create); `tests/unit/test_contract.py` (update count + tier)

**Interfaces:**
- Consumes: `SessionManager.read_events` / `ReadResult` (Task 2), `_resolve_session` (existing).
- Produces: `read_hook_events(since_seq: int = 0, limit: int = 100, session_id: str = "") -> str`; envelope `{"summary", "events", "next_seq", "buffered_remaining", "has_more", "lost"}`.

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_read_hook_events.py`:

```python
import json
import pytest

from pare_frida_mcp import tools as T
from pare_frida_mcp.core.sessions import SessionManager


class _FakeScript:
    def on(self, *a, **k): pass


class _FakeFrida:
    def __init__(self, detached=False): self.is_detached = detached


def _live_session_with_events(n):
    sid = T.MANAGER.register_session(script=_FakeScript(), pid=1, name="x")
    T.MANAGER.get(sid).frida_session = _FakeFrida(False)
    for seq in range(1, n + 1):
        T.MANAGER.get(sid)._events.append(
            {"seq": seq, "class": "C", "method": "m", "args": [], "ret": None})
    return sid


@pytest.mark.asyncio
async def test_reads_events_via_active_session():
    _live_session_with_events(3)
    res = json.loads(await T.read_hook_events())   # no session_id, since_seq=0
    assert res.get("error") is not True
    assert [e["seq"] for e in res["events"]] == [1, 2, 3]
    assert res["has_more"] is False and res["next_seq"] == 3 and res["lost"] == 0


@pytest.mark.asyncio
async def test_has_more_summary_directs_next_cursor():
    sid = _live_session_with_events(5)
    res = json.loads(await T.read_hook_events(since_seq=0, limit=2, session_id=sid))
    assert res["has_more"] is True and res["next_seq"] == 2
    assert "since_seq=2" in res["summary"]


@pytest.mark.asyncio
async def test_limit_is_clamped():
    sid = _live_session_with_events(3)
    res = json.loads(await T.read_hook_events(limit=10**9, session_id=sid))
    assert res.get("error") is not True and len(res["events"]) == 3


@pytest.mark.asyncio
async def test_no_live_session_errors_with_attach_hint():
    res = json.loads(await T.read_hook_events())
    assert res["error"] is True and "attach" in json.dumps(res).lower()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src <venv>/bin/python -m pytest tests/unit/test_read_hook_events.py -q`
Expected: FAIL (`AttributeError: module 'pare_frida_mcp.tools' has no attribute 'read_hook_events'`).

- [ ] **Step 3: Implement the tool**

In `src/pare_frida_mcp/tools.py`, add near the other constants:

```python
_EVENT_LIMIT_MAX = 500
_EVENT_WIRE_BUDGET = 3072   # below host max_tool_bytes so a normal read never trips the stub


def _clamp(v: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, v))
```

Add the tool (place it after `java_hook_remove`):

```python
async def read_hook_events(since_seq: int = 0, limit: int = 100,
                           session_id: str = "") -> str:
    try:
        s = _resolve_session(session_id)
        r = MANAGER.read_events(s.id, since_seq=max(0, since_seq),
                                limit=_clamp(limit, 1, _EVENT_LIMIT_MAX),
                                max_bytes=_EVENT_WIRE_BUDGET)
        note = ""
        if r.lost:
            note += f"; {r.lost} evicted before seq {since_seq} - read more often"
        if r.has_more:
            note += (f"; {r.buffered_remaining} more - call again with "
                     f"since_seq={r.next_seq}")
        return _ok(f"{len(r.events)} events{note}", events=r.events,
                   next_seq=r.next_seq, buffered_remaining=r.buffered_remaining,
                   has_more=r.has_more, lost=r.lost)
    except Exception as e:
        return _err("read_hook_events failed", e)
```

- [ ] **Step 4: Add the contract entry**

In `src/pare_frida_mcp/contract.py`, add to `TOOL_SPECS` (after `java_hook_remove`):

```python
    ToolSpec("read_hook_events", "low",
             "Read buffered java_hook events for a session (non-destructive). "
             "Pass since_seq = the last seq you saw (0 first time); returns "
             "events with seq > since_seq, decoded args + return value. "
             "has_more + next_seq means call again with since_seq=next_seq to "
             "page the rest; lost>0 means old events were evicted (read more "
             "often / raise the buffer). An EMPTY result means the hooked action "
             "has not been triggered yet - retry after the app action, do not "
             "remove the hook. Tier low: the sensitive act (choosing what to "
             "capture) was already gated at java_hook.",
             _in(since_seq={"type": "integer"}, limit={"type": "integer"},
                 session_id={"type": "string"})),
```

- [ ] **Step 5: Update the contract tests**

In `tests/unit/test_contract.py`, change `test_tool_count_is_17`:

```python
def test_tool_count_is_18():
    # 17 (+ enumerate_classes/methods) -> 18 (+ read_hook_events)
    assert len(TOOL_SPECS) == 18

def test_read_hook_events_is_low():
    by_name = {s.name: s for s in TOOL_SPECS}
    assert by_name["read_hook_events"].risk_tier == "low"
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `PYTHONPATH=src <venv>/bin/python -m pytest tests/unit/test_read_hook_events.py tests/unit/test_contract.py -q`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add src/pare_frida_mcp/tools.py src/pare_frida_mcp/contract.py tests/unit/test_read_hook_events.py tests/unit/test_contract.py
git commit -m "feat(tools): read_hook_events cursor tool (tier low)"
```

---

### Task 4: `java_hook` overload as a descriptor list (Python side)

**Files:**
- Modify: `src/pare_frida_mcp/android/java.py` (`java_hook` pass-through)
- Modify: `src/pare_frida_mcp/tools.py` (`java_hook`, `java_hook_remove` signatures + ambiguity handling)
- Modify: `src/pare_frida_mcp/contract.py` (`java_hook` / `java_hook_remove` `overload` schema + description)
- Test: `tests/unit/test_java_hook_overload.py` (create)

**Interfaces:**
- Consumes: agent export `java_hook_install(cls, method, overload_list) -> dict` returning either `{"hook": "<cls>.<method>", "since_seq": int}` or `{"ambiguous": true, "overloads": [["[B"], ["[B","int","int"]]}` (Task 5 implements the agent side).
- Produces: `java_hook(cls, method, overload=None, session_id="")`, `java_hook_remove(cls, method, overload=None, session_id="")` — `overload` is a `list[str]` of frida type descriptors.

- [ ] **Step 1: Write the failing test**

Create `tests/unit/test_java_hook_overload.py`:

```python
import json
import pytest

from pare_frida_mcp import tools as T


class _Exports:
    def __init__(self, result):
        self._result = result
        self.calls = []
    def java_hook_install(self, cls, method, overload):
        self.calls.append((cls, method, overload))
        return self._result


class _FakeScript:
    def __init__(self, result): self.exports_sync = _Exports(result)
    def on(self, *a, **k): pass


class _FakeFrida:
    def __init__(self): self.is_detached = False


def _session(result):
    sid = T.MANAGER.register_session(script=_FakeScript(result), pid=1, name="x")
    T.MANAGER.get(sid).frida_session = _FakeFrida()
    return sid


@pytest.mark.asyncio
async def test_overload_list_passed_through():
    sid = _session({"hook": "C.write", "since_seq": 7})
    res = json.loads(await T.java_hook(cls="C", method="write",
                                       overload=["[B", "int", "int"], session_id=sid))
    assert res.get("error") is not True
    assert res["hook"]["since_seq"] == 7
    assert T.MANAGER.get(sid).script.exports_sync.calls == [("C", "write", ["[B", "int", "int"])]


@pytest.mark.asyncio
async def test_ambiguous_overload_returns_choices():
    sid = _session({"ambiguous": True, "overloads": [["[B"], ["[B", "int", "int"]]})
    res = json.loads(await T.java_hook(cls="C", method="write", session_id=sid))
    assert res["error"] is True
    assert res["overloads"] == [["[B"], ["[B", "int", "int"]]
    assert "overload" in res["summary"].lower()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `PYTHONPATH=src <venv>/bin/python -m pytest tests/unit/test_java_hook_overload.py -q`
Expected: FAIL (current `java_hook` passes `overload or ""` and has no ambiguity branch; signature mismatch).

- [ ] **Step 3: Update `android/java.py`**

In `src/pare_frida_mcp/android/java.py`, change `java_hook`:

```python
def java_hook(script, cls: str, method: str, overload: list | None = None) -> dict:
    return script.exports_sync.java_hook_install(cls, method, overload or [])
```

- [ ] **Step 4: Update `tools.java_hook` / `java_hook_remove`**

In `src/pare_frida_mcp/tools.py`:

```python
async def java_hook(cls: str, method: str, overload: list | None = None,
                    session_id: str = "") -> str:
    try:
        s = _resolve_session(session_id)
        res = java_mod.java_hook(s.script, cls, method, overload)
        if isinstance(res, dict) and res.get("ambiguous"):
            return json.dumps({
                "summary": f"{cls}.{method} is overloaded - retry java_hook with "
                           f"'overload' set to one of these descriptor lists",
                "error": True, "overloads": res.get("overloads", [])})
        return _ok(f"hook installed: {cls}.{method}", hook=res)
    except Exception as e:
        return _err("java_hook failed", e)


async def java_hook_remove(cls: str, method: str, overload: list | None = None,
                           session_id: str = "") -> str:
    try:
        s = _resolve_session(session_id)
        res = s.script.exports_sync.java_hook_remove(cls, method, overload or [])
        return _ok(f"hook removed: {cls}.{method}", removed=res)
    except Exception as e:
        return _err("java_hook_remove failed", e)
```

- [ ] **Step 5: Update the contract schema + description**

In `src/pare_frida_mcp/contract.py`, replace the `java_hook` and `java_hook_remove` specs:

```python
    ToolSpec("java_hook", "high",
             "Install an OBSERVING Java method hook (captures decoded arguments "
             "AND the return value; the original still runs). Works on app and "
             "framework classes. 'overload' is an ordered list of frida type "
             "descriptors, one per parameter (e.g. [\"[B\",\"int\",\"int\"]); "
             "omit it for a non-overloaded method - if the method is overloaded "
             "the call returns the available descriptor lists to choose from. "
             "Read what the hook captured with read_hook_events (start at the "
             "since_seq this call returns). WARNING: hooking an ultra-hot method "
             "(e.g. String.<init>) floods the buffer; a per-thread guard prevents "
             "recursion but the signal will be noisy.",
             _in(session_id={"type": "string"}, cls={"type": "string"},
                 method={"type": "string"},
                 overload={"type": "array", "items": {"type": "string"}})),
    ToolSpec("java_hook_remove", "low", "Remove a previously installed Java method "
             "hook. 'overload' is the same descriptor list used to install it.",
             _in(session_id={"type": "string"}, cls={"type": "string"},
                 method={"type": "string"},
                 overload={"type": "array", "items": {"type": "string"}})),
```

- [ ] **Step 6: Fix any existing java_hook callers in tests**

Run: `PYTHONPATH=src <venv>/bin/python -m pytest tests/unit -q`
Expected: PASS. If `tests/device/test_android_flows.py` calls `java_hook(...)` with no overload it still works (defaults to `None`). Update any test passing `overload=""` to `overload=["..."]` or omit it.

- [ ] **Step 7: Commit**

```bash
git add src/pare_frida_mcp/android/java.py src/pare_frida_mcp/tools.py src/pare_frida_mcp/contract.py tests/unit/test_java_hook_overload.py
git commit -m "feat(tools): java_hook overload as descriptor list + ambiguity choices"
```

---

### Task 5: Agent — decode, guarded emit, seq baseline, overload spread

**Files:**
- Modify: `src/pare_frida_mcp/agent/src/index.ts` (`javaHookInstall`, `javaHookRemove`, helpers)
- Build: `src/pare_frida_mcp/agent/dist/agent.js` (via `npm run build`)

**Interfaces:**
- Consumes: nothing new.
- Produces: the event shape `{hook:true, seq, class, method, overload, args, ret, threw, thread}` (and `{...,reentrant:true}`); `javaHookInstall(cls, method, overloadList)` → `{hook, since_seq}` or `{ambiguous:true, overloads:[[str]...]}`.

> This file is TypeScript compiled into the Frida agent; it cannot be unit-tested (needs the Frida runtime + a live VM). It is verified by Task 6's live acceptance. Make the change, rebuild, and confirm the bundle compiles.

- [ ] **Step 1: Replace the hook/helper section of `index.ts`**

Add helpers above `rpc.exports` and replace `javaHookInstall` / `javaHookRemove`:

```ts
const CAP = 4096;
let SEQ = 0;
const active = new Set<number>();                 // thread-ids currently inside a hook body

function clip(s: string): string { return s.length > CAP ? s.slice(0, CAP) : s; }

function hexJS(v: any, n: number): string {
  let s = "";
  for (let i = 0; i < n; i++) { const b = v[i] & 0xff; s += (b < 16 ? "0" : "") + b.toString(16); }
  return s;
}

function utf8JS(v: any, n: number): string | null {
  // manual UTF-8 decode of signed bytes; return null on any invalid sequence
  let out = "", i = 0;
  while (i < n) {
    const b0 = v[i] & 0xff;
    if (b0 < 0x80) { out += String.fromCharCode(b0); i += 1; continue; }
    let cp: number, len: number;
    if (b0 >= 0xc2 && b0 <= 0xdf) { cp = b0 & 0x1f; len = 2; }
    else if (b0 >= 0xe0 && b0 <= 0xef) { cp = b0 & 0x0f; len = 3; }
    else if (b0 >= 0xf0 && b0 <= 0xf4) { cp = b0 & 0x07; len = 4; }
    else return null;
    if (i + len > n) return null;
    for (let k = 1; k < len; k++) { const bk = v[i + k] & 0xff; if (bk < 0x80 || bk > 0xbf) return null; cp = (cp << 6) | (bk & 0x3f); }
    out += String.fromCodePoint(cp); i += len;
  }
  return out;
}

function describe(v: any): any {
  if (v === null || v === undefined) return null;
  if (typeof v !== "object") return v;
  try {
    const cn = v.$className;
    if (cn === "java.lang.String") return clip(v.toString());
    if (cn === undefined && typeof v.length === "number" &&
        (v.length === 0 || typeof v[0] === "number")) {
      const n = Math.min(v.length, CAP);
      const out: any = { hex: hexJS(v, n), len: v.length };
      const u = utf8JS(v, n);
      if (u !== null) out.utf8 = u;
      return out;
    }
    return { class: cn || "?", value: clip(String(v)) };
  } catch (e) { return { error: String(e) }; }
}
```

Replace `javaHookInstall` and `javaHookRemove` in `rpc.exports`:

```ts
  javaHookInstall(cls: string, method: string, overload?: string[]) {
    let result: any = { hook: `${cls}.${method}`, since_seq: SEQ };
    Java.perform(() => {
      const klass: any = Java.use(cls);
      const m: any = klass[method];
      let target: any;
      if (overload && overload.length) {
        target = m.overload.apply(m, overload);
      } else if (m.overloads && m.overloads.length > 1) {
        result = { ambiguous: true,
          overloads: m.overloads.map((o: any) => o.argumentTypes.map((t: any) => t.className)) };
        return;
      } else {
        target = m;
      }
      const ov: string[] = (overload && overload.length)
        ? overload
        : (target.argumentTypes ? target.argumentTypes.map((t: any) => t.className) : []);
      target.implementation = function (...args: any[]) {
        const tid = Process.getCurrentThreadId();
        if (active.has(tid)) {                                   // re-entrancy guard
          send({ hook: true, seq: ++SEQ, class: cls, method, overload: ov, reentrant: true, thread: tid });
          return target.apply(this, args);
        }
        active.add(tid);
        const argsD = args.map(describe);
        let retD: any = null, threw = false;
        try {
          const r = target.apply(this, args);
          retD = describe(r);
          return r;
        } catch (e: any) {
          threw = true; retD = { error: String(e) };
          throw e;
        } finally {
          send({ hook: true, seq: ++SEQ, class: cls, method, overload: ov,
                 args: argsD, ret: retD, threw, thread: tid });
          active.delete(tid);
        }
      };
      result = { hook: `${cls}.${method}`, since_seq: SEQ };
    });
    return result;
  },
  javaHookRemove(cls: string, method: string, overload?: string[]) {
    Java.perform(() => {
      const klass: any = Java.use(cls);
      const m: any = klass[method];
      const target: any = (overload && overload.length) ? m.overload.apply(m, overload) : m;
      target.implementation = null;
    });
    return { removed: `${cls}.${method}` };
  },
```

- [ ] **Step 2: Rebuild the bundle**

Run: `cd src/pare_frida_mcp/agent && npm run build`
Expected: exits 0; `dist/agent.js` mtime updates. Fix any TypeScript compile error before proceeding.

- [ ] **Step 3: Run the full unit suite (no regression)**

Run: `PYTHONPATH=src <venv>/bin/python -m pytest tests/unit -q`
Expected: PASS (agent change does not affect stubbed unit tests).

- [ ] **Step 4: Commit**

```bash
git add src/pare_frida_mcp/agent/src/index.ts src/pare_frida_mcp/agent/dist/agent.js
git commit -m "feat(agent): decoded+guarded hook events, seq baseline, overload spread"
```

---

### Task 6: Live acceptance (KeyStore end-to-end)

**Files:** none (verification only; uses a live emulator with frida-server and the OMTG app).

**Interfaces:** Consumes the full stack (Tasks 1-5).

> Requires: `adb` device up, frida-server running, `sg.vp.owasp_mobile.omtg_android` installed, on the OMTG_DATAST_001_KeyStore screen. Drive via a small frida client that loads the freshly built `dist/agent.js` and calls the rpc exports, OR via a running PARE session.

- [ ] **Step 1: Verify byte[] decode + overload resolution (ENCRYPT path)**

Install: `javaHookInstall("javax.crypto.CipherOutputStream", "write", ["[B"])` → expect `{hook, since_seq}`.
Trigger: type text in Clear Text, press ENCRYPT.
Read: `read_events(since_seq=<baseline>)` → expect an event with `class="javax.crypto.CipherOutputStream"`, `method="write"`, `args[0].utf8` == the typed plaintext, `args[0].hex` present.
Expected: PASS — the decoded plaintext appears (the proof the walkthrough deferred).

- [ ] **Step 2: Verify overload ambiguity path**

Install with no overload on an overloaded method: `javaHookInstall("javax.crypto.CipherOutputStream", "write")`.
Expected: returns `{ambiguous:true, overloads:[["[B"], ["[B","int","int"], ["int"]]}` (exact list may vary) — no exception.

- [ ] **Step 3: Verify re-entrancy guard (no crash)**

Install: `javaHookInstall("java.lang.String", "$init", ["[B","int","int","java.lang.String"])`.
Trigger: press DECRYPT.
Expected: the target process does NOT crash; events carry `reentrant:true` (no unbounded recursion). Remove the hook afterward.

- [ ] **Step 4: Verify idempotent read + pagination**

Call `read_events(since_seq=0, limit=1)` twice with the SAME `since_seq`.
Expected: identical first event both times (non-destructive); `has_more=true`, `next_seq` points to the next unread seq.

- [ ] **Step 5: Record results in the PR description**

Capture the decoded-plaintext event and the no-crash result as the live-acceptance evidence for the PR.

---

## Notes for the implementer

- Use the project venv that has `pare_frida_mcp` importable + `pytest` + `pytest-asyncio`; conftest stubs `frida` so unit tests need no device.
- Keep `session_id` last with a default on every tool.
- Do not reintroduce a `dropped` counter — `lost` is derived on read from `seq`.
- After all tasks: full suite green, bundle rebuilt, then open a PR onto `main` for review (do not merge without sign-off).
