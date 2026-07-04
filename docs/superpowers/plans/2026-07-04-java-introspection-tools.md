# Java Introspection Tools Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add two read-only Java introspection MCP tools — `enumerate_classes` and `enumerate_methods` — so the model discovers classes/methods via bounded tool calls instead of hand-writing Frida JS through the `critical` `execute_script` gate.

**Architecture:** Both tools run on the existing bundled-agent rpc path (`script.exports_sync.<name>()`), the same seam `enumerate_modules` and `java_hook` use. `enumerate_classes` wires the already-built `javaEnumerate` export; `enumerate_methods` adds one new `javaEnumerateMethods` export (recompiled into `dist/agent.js`). Thin wrappers in `android/java.py`, tools in `tools.py`, specs in `contract.py`. The server auto-registers any `ToolSpec` whose `name` matches a function in `tools.py`.

**Tech Stack:** Python 3.12 (pytest, pytest-asyncio), FastMCP, Frida 17 (`frida-java-bridge`), TypeScript compiled via `frida-compile`.

## Global Constraints

- Both new tools are risk tier **`low`** (read-only; no memory writes, no code exec). `execute_script` stays `critical`.
- Envelope shapes (match `enumerate_modules`): `enumerate_classes` → `{"summary": "<n> classes", "classes": [<fqcn>...]}`; `enumerate_methods` → `{"summary": "<n> methods for <cls>", "methods": [{"name": <str>, "signature": <str>}...]}`.
- Frida snake-cases rpc export names on the Python side: TS `javaEnumerate` → `exports_sync.java_enumerate`; TS `javaEnumerateMethods` → `exports_sync.java_enumerate_methods` (precedent: `javaHookInstall` → `java_hook_install` in `android/java.py`).
- `getDeclaredMethods()` is declared-only by design (excludes inherited framework methods).
- Test runner: `/home/edible/Projects/PARE/.venv/bin/python -m pytest` run from the `pare-frida-mcp` repo root (that venv has `frida` + editable `pare_frida_mcp`). pare-frida-mcp has no own venv.
- Use `_ok(summary, **extra)` and `_err(summary, exc)` helpers already in `tools.py`.

---

## File Structure

- `src/pare_frida_mcp/android/java.py` — MODIFY: add `enumerate_classes(script, filter)` and `enumerate_methods(script, cls)` thin wrappers.
- `src/pare_frida_mcp/tools.py` — MODIFY: add `async def enumerate_classes(...)` and `async def enumerate_methods(...)`.
- `src/pare_frida_mcp/contract.py` — MODIFY: add two `ToolSpec` entries (tier `low`).
- `src/pare_frida_mcp/agent/src/index.ts` — MODIFY (Task 2): add `javaEnumerateMethods` rpc export.
- `src/pare_frida_mcp/agent/dist/agent.js` — REGENERATE (Task 2): `npm run build`.
- `tests/unit/test_java_introspection.py` — CREATE: unit tests for both tools + tier assertions.

---

## Task 1: enumerate_classes (wire the existing javaEnumerate export)

**Files:**
- Modify: `src/pare_frida_mcp/android/java.py`
- Modify: `src/pare_frida_mcp/tools.py`
- Modify: `src/pare_frida_mcp/contract.py`
- Test: `tests/unit/test_java_introspection.py`

**Interfaces:**
- Consumes: `MANAGER.get(sid).script` (a live Session's frida script), `validate_session_id`, `_ok`/`_err` (all in `tools.py`); the existing `javaEnumerate` rpc export in `dist/agent.js` (no JS change this task).
- Produces: `java_mod.enumerate_classes(script, filter="") -> list[str]`; MCP tool `enumerate_classes(session_id, filter="")`.

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_java_introspection.py`:

```python
import json

import pytest

from pare_frida_mcp import tools as T
from pare_frida_mcp.android import java as java_mod
from pare_frida_mcp.contract import TOOL_SPECS
from pare_frida_mcp.ids import new_session_id


class _DummySession:
    """Minimal stand-in for a live Session (mirrors test_tools_enum)."""
    def __init__(self):
        self.script = object()
        self.frida_session = None

    def flush(self):
        pass


def _by_name():
    return {s.name: s for s in TOOL_SPECS}


@pytest.mark.asyncio
async def test_enumerate_classes_returns_envelope(monkeypatch):
    sid = new_session_id()
    T.MANAGER._sessions[sid] = _DummySession()
    classes = ["a.B", "a.C", "a.D"]
    monkeypatch.setattr(java_mod, "enumerate_classes", lambda script, filter: classes)
    try:
        doc = json.loads(await T.enumerate_classes(sid, "a"))
        assert doc.get("error") is not True, doc
        assert doc["classes"] == classes
        assert doc["summary"] == "3 classes"
    finally:
        T.MANAGER._sessions.pop(sid, None)


@pytest.mark.asyncio
async def test_enumerate_classes_no_live_session_errors():
    res = json.loads(await T.enumerate_classes(new_session_id(), ""))
    assert res.get("error") is True


def test_enumerate_classes_is_low_tier():
    assert _by_name()["enumerate_classes"].risk_tier == "low"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `/home/edible/Projects/PARE/.venv/bin/python -m pytest tests/unit/test_java_introspection.py -q`
Expected: FAIL — `AttributeError: module 'pare_frida_mcp.tools' has no attribute 'enumerate_classes'` (and `KeyError: 'enumerate_classes'` in the tier test).

- [ ] **Step 3: Add the wrapper**

In `src/pare_frida_mcp/android/java.py`, append after `java_hook`:

```python
def enumerate_classes(script, filter: str = "") -> list[str]:
    return script.exports_sync.java_enumerate(filter)
```

- [ ] **Step 4: Add the tool**

In `src/pare_frida_mcp/tools.py`, add after `enumerate_exports` (uses the already-imported `java_mod`):

```python
async def enumerate_classes(session_id: str, filter: str = "") -> str:
    try:
        sid = validate_session_id(session_id)
        s = MANAGER.get(sid)
        rows = java_mod.enumerate_classes(s.script, filter)
        return _ok(f"{len(rows)} classes", classes=rows)
    except Exception as e:
        return _err("enumerate_classes failed", e)
```

- [ ] **Step 5: Add the contract spec**

In `src/pare_frida_mcp/contract.py`, add to `TOOL_SPECS` after the `enumerate_exports` entry:

```python
    ToolSpec("enumerate_classes", "low",
             "List LOADED Java classes in an ATTACHED process (requires session_id "
             "from attach), filtered by substring. Classes load lazily - navigate "
             "into the screen/activity you care about first, then enumerate. "
             "Returns the loaded class list (capped at 500).",
             _in(session_id={"type": "string"}, filter={"type": "string"})),
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `/home/edible/Projects/PARE/.venv/bin/python -m pytest tests/unit/test_java_introspection.py -q`
Expected: PASS (3 passed).

- [ ] **Step 7: Run the full unit suite (no regressions)**

Run: `/home/edible/Projects/PARE/.venv/bin/python -m pytest tests/unit -q`
Expected: PASS (all existing + 3 new).

- [ ] **Step 8: Commit**

```bash
git add src/pare_frida_mcp/android/java.py src/pare_frida_mcp/tools.py src/pare_frida_mcp/contract.py tests/unit/test_java_introspection.py
git commit -m "feat(tools): enumerate_classes (wire javaEnumerate export, tier low)"
```

---

## Task 2: enumerate_methods (new rpc export + recompile + tool)

**Files:**
- Modify: `src/pare_frida_mcp/agent/src/index.ts`
- Regenerate: `src/pare_frida_mcp/agent/dist/agent.js`
- Modify: `src/pare_frida_mcp/android/java.py`
- Modify: `src/pare_frida_mcp/tools.py`
- Modify: `src/pare_frida_mcp/contract.py`
- Test: `tests/unit/test_java_introspection.py`

**Interfaces:**
- Consumes: `MANAGER.get(sid).script`, `validate_session_id`, `_ok`/`_err`; the new `javaEnumerateMethods` rpc export.
- Produces: `java_mod.enumerate_methods(script, cls) -> list[dict]` (each `{"name": str, "signature": str}`); MCP tool `enumerate_methods(session_id, cls)`.

- [ ] **Step 1: Write the failing tests**

Append to `tests/unit/test_java_introspection.py`:

```python
@pytest.mark.asyncio
async def test_enumerate_methods_returns_envelope(monkeypatch):
    sid = new_session_id()
    T.MANAGER._sessions[sid] = _DummySession()
    methods = [
        {"name": "encryptString", "signature": "public void C.encryptString(java.lang.String)"},
        {"name": "decryptString", "signature": "public void C.decryptString(java.lang.String)"},
    ]
    monkeypatch.setattr(java_mod, "enumerate_methods", lambda script, cls: methods)
    try:
        doc = json.loads(await T.enumerate_methods(sid, "a.C"))
        assert doc.get("error") is not True, doc
        assert doc["methods"] == methods
        assert doc["summary"] == "2 methods for a.C"
    finally:
        T.MANAGER._sessions.pop(sid, None)


@pytest.mark.asyncio
async def test_enumerate_methods_no_live_session_errors():
    res = json.loads(await T.enumerate_methods(new_session_id(), "a.C"))
    assert res.get("error") is True


def test_enumerate_methods_is_low_tier():
    assert _by_name()["enumerate_methods"].risk_tier == "low"
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `/home/edible/Projects/PARE/.venv/bin/python -m pytest tests/unit/test_java_introspection.py -q`
Expected: FAIL — `AttributeError: ... has no attribute 'enumerate_methods'` and `KeyError: 'enumerate_methods'`.

- [ ] **Step 3: Add the rpc export**

In `src/pare_frida_mcp/agent/src/index.ts`, add inside the `rpc.exports = { ... }` object (after `javaEnumerate`):

```ts
  javaEnumerateMethods(cls: string) {
    const out: { name: string; signature: string }[] = [];
    Java.perform(() => {
      const klass = Java.use(cls);
      klass.class.getDeclaredMethods()
        .forEach((m: any) => out.push({ name: m.getName(), signature: m.toString() }));
    });
    return out;
  },
```

- [ ] **Step 4: Recompile the bundled agent**

Run: `cd src/pare_frida_mcp/agent && npm run build && cd -`
Expected: `frida-compile` writes `dist/agent.js` with no error.

- [ ] **Step 5: Verify the export is in the bundle**

Run: `grep -c javaEnumerateMethods src/pare_frida_mcp/agent/dist/agent.js`
Expected: at least `1` (the export key is preserved in the compiled bundle, like `modules:`/`javaEnumerate`).

- [ ] **Step 6: Add the wrapper**

In `src/pare_frida_mcp/android/java.py`, append:

```python
def enumerate_methods(script, cls: str) -> list[dict]:
    return script.exports_sync.java_enumerate_methods(cls)
```

- [ ] **Step 7: Add the tool**

In `src/pare_frida_mcp/tools.py`, add after `enumerate_classes`:

```python
async def enumerate_methods(session_id: str, cls: str) -> str:
    try:
        sid = validate_session_id(session_id)
        s = MANAGER.get(sid)
        rows = java_mod.enumerate_methods(s.script, cls)
        return _ok(f"{len(rows)} methods for {cls}", methods=rows)
    except Exception as e:
        return _err("enumerate_methods failed", e)
```

- [ ] **Step 8: Add the contract spec**

In `src/pare_frida_mcp/contract.py`, add to `TOOL_SPECS` after the `enumerate_classes` entry:

```python
    ToolSpec("enumerate_methods", "low",
             "List a Java class's DECLARED methods in an ATTACHED process "
             "(requires session_id). Declared-only (excludes inherited framework "
             "methods). Returns {name, signature} per method; signature carries "
             "parameter types for java_hook overload resolution.",
             _in(session_id={"type": "string"}, cls={"type": "string"})),
```

- [ ] **Step 9: Run the tests to verify they pass**

Run: `/home/edible/Projects/PARE/.venv/bin/python -m pytest tests/unit/test_java_introspection.py -q`
Expected: PASS (6 passed).

- [ ] **Step 10: Run the full unit suite (no regressions)**

Run: `/home/edible/Projects/PARE/.venv/bin/python -m pytest tests/unit -q`
Expected: PASS (all existing + 6 new).

- [ ] **Step 11: Commit**

```bash
git add src/pare_frida_mcp/agent/src/index.ts src/pare_frida_mcp/agent/dist/agent.js src/pare_frida_mcp/android/java.py src/pare_frida_mcp/tools.py src/pare_frida_mcp/contract.py tests/unit/test_java_introspection.py
git commit -m "feat(tools): enumerate_methods (new javaEnumerateMethods export, tier low)"
```

---

## Final verification (live — run by the controller, not a subagent)

Unit tests use a monkeypatched wrapper, so they never exercise the real bundle. Prove the JS export + real frida path against the live OWASP target once both tasks are green:

1. Ensure the emulator is up and the OMTG app (`sg.vp.owasp_mobile.omtg_android`) is running, and **navigate into the KeyStore challenge on-screen** (its class loads lazily on entry).
2. Attach, enumerate classes, then methods (via `pare_frida_mcp.tools` against a real session, or through the daemon):

```
enumerate_classes(session_id, filter="OMTG")
# expect the loaded OMTG_* classes to include OMTG_DATAST_001_KeyStore

enumerate_methods(session_id, "sg.vp.owasp_mobile.OMTG_Android.OMTG_DATAST_001_KeyStore")
# expect exactly these 5 declared methods (ground truth from dexdump):
#   <init>, createNewKeys, encryptString, decryptString, onCreate
```

**Acceptance:** `enumerate_methods` returns the 5 ground-truth methods with signatures; both tools report tier `low`; `execute_script` remains `critical`.
