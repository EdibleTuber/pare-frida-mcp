# Java Object-State Reads Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the model tools to read Java object state — `java_read_fields` (pull instance/static fields off a class on demand) and a `capture_this` parameter on `java_hook` (push-snapshot `this`'s fields at the hook site) — so it can recover a secret a method computes into a field instead of returning.

**Architecture:** Both additions live in the bundled Frida agent (`agent/src/index.ts`), which imports `frida-java-bridge` and is the only place `Java.*` works (bare `execute_script` has no bridge on Frida 17). Python plumbing follows the existing three-layer pattern: a thin `android/java.py` wrapper over `script.exports_sync.<name>`, an async handler in `tools.py`, and a `ToolSpec` in `contract.py`. Field values reuse the agent's existing `describe()` serializer so they decode identically to hook args/returns.

**Tech Stack:** Python 3 + FastMCP (server/tools), TypeScript compiled with `frida-compile` (bundled agent), pytest + pytest-asyncio (tests), frida-java-bridge (Java runtime access).

## Global Constraints

- **Repo/branch:** `pare-frida-mcp`, branch `feat/java-object-state-reads` (already created; the design spec is committed there at `docs/superpowers/specs/2026-07-22-java-object-state-reads-design.md`).
- **No new dependencies.** Reuse `describe()` (`agent/src/index.ts:34`), the per-thread reentrancy guard (`active` set, `index.ts:5,107-118`), `_ok`/`_err`/`_resolve_session` (`tools.py:26-49`), and the `_in(...)` schema helper (`contract.py:24`).
- **Risk tiers (exact):** `java_read_fields` = `high`; `java_hook` stays `high`; `read_hook_events` stays `low`; `execute_script` stays `critical`.
- **Bounds:** ≤ 10 instances, ≤ 64 declared fields on the dump-all path, per-field value clipped to `CAP = 4096` by `describe()` (`index.ts:7`). Any cap hit sets `capped: true` and is noted in the summary.
- **Static-vs-instance dispatch is by the field's own modifier** (`java.lang.reflect.Modifier.isStatic` via `getDeclaredField`), never guessed from instance count.
- **Field/method name collision:** frida-java-bridge remaps a field whose name collides with a same-named method to a suffixed accessor `_<name>`. Resolve every field name through the shared `resolveField` helper; never index by raw name blind. (Verify the exact collision spelling against the pinned frida-java-bridge version at implementation time; `_<name>` is the documented default.)
- **`capture_this` is captured on the NON-THROW path only, inside the `active`-guard bracket.** Hook events remain byte-identical when `capture_this` is absent (the `this` key is only added when fields were captured).
- **Agent recompile:** after any `agent/src/index.ts` change, rebuild the bundle with `npm run build` in `agent/` (`frida-compile src/index.ts -o dist/agent.js -c`) and commit `agent/dist/agent.js` alongside the source.
- **Test runner:** `PYTHONPATH=src python3 -m pytest <path> -q` from the repo root (no project virtualenv is present; `python3` is the interpreter).

---

### Task 1: Python plumbing — `java_read_fields` handler + `capture_this` forwarding

**Files:**
- Modify: `src/pare_frida_mcp/android/java.py` (add `java_read_fields`; extend `java_hook`)
- Modify: `src/pare_frida_mcp/tools.py` (add `java_read_fields` handler; add `capture_this` param to `java_hook` handler)
- Test: `tests/unit/test_java_object_state.py` (new)
- Modify: `tests/unit/test_java_hook_overload.py` (fake `java_hook_install` now receives 4 args)

**Interfaces:**
- Consumes: `describe()`-shaped field values from the agent (a `str` for a String field, a `{hex,utf8,len}` dict for a byte array, `null`, or `{error:…}`). In these unit tests the agent call is monkeypatched, so its return is canned.
- Produces (later tasks + server rely on these exact names/signatures):
  - `java_mod.java_read_fields(script, cls: str, fields: list | None) -> dict` returning `{cls, instance_count, instances:[{fields:{}}], static_fields:{}, capped}`.
  - `java_mod.java_hook(script, cls, method, overload=None, capture_this=None) -> dict`.
  - `tools.java_read_fields(cls: str, fields: list | None = None, session_id: str = "") -> str`.
  - `tools.java_hook(cls, method, overload=None, capture_this=None, session_id="") -> str`.

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_java_object_state.py`:

```python
import json
import pytest

from pare_frida_mcp import tools as T
from pare_frida_mcp.android import java as java_mod
from pare_frida_mcp.ids import new_session_id


class _DummySession:
    """Minimal stand-in for a live Session (mirrors test_java_introspection)."""
    def __init__(self):
        self.script = object()
        self.frida_session = None
    def flush(self):
        pass


def _sid():
    sid = new_session_id()
    T.MANAGER._sessions[sid] = _DummySession()
    return sid


@pytest.mark.asyncio
async def test_read_fields_instance_envelope(monkeypatch):
    sid = _sid()
    canned = {"cls": "a.C", "instance_count": 1,
              "instances": [{"fields": {"plainText": "s3cr3t"}}],
              "static_fields": {}, "capped": False}
    monkeypatch.setattr(java_mod, "java_read_fields", lambda script, cls, fields: canned)
    try:
        doc = json.loads(await T.java_read_fields(cls="a.C", fields=["plainText"], session_id=sid))
        assert doc.get("error") is not True, doc
        assert doc["instances"] == [{"fields": {"plainText": "s3cr3t"}}]
        assert doc["instance_count"] == 1
        assert 'plainText="s3cr3t"' in doc["summary"]   # value folded inline
    finally:
        T.MANAGER._sessions.pop(sid, None)


@pytest.mark.asyncio
async def test_read_fields_empty_gives_guidance(monkeypatch):
    sid = _sid()
    canned = {"cls": "a.C", "instance_count": 0, "instances": [],
              "static_fields": {}, "capped": False}
    monkeypatch.setattr(java_mod, "java_read_fields", lambda script, cls, fields: canned)
    try:
        doc = json.loads(await T.java_read_fields(cls="a.C", session_id=sid))
        assert doc.get("error") is not True, doc
        assert "trigger" in doc["summary"] and "capture_this" in doc["summary"]
    finally:
        T.MANAGER._sessions.pop(sid, None)


@pytest.mark.asyncio
async def test_read_fields_static_only(monkeypatch):
    sid = _sid()
    canned = {"cls": "a.C", "instance_count": 0, "instances": [],
              "static_fields": {"SECRET": "abc"}, "capped": False}
    monkeypatch.setattr(java_mod, "java_read_fields", lambda script, cls, fields: canned)
    try:
        doc = json.loads(await T.java_read_fields(cls="a.C", fields=["SECRET"], session_id=sid))
        assert doc.get("error") is not True, doc
        assert doc["static_fields"] == {"SECRET": "abc"}
        assert "static field" in doc["summary"]
    finally:
        T.MANAGER._sessions.pop(sid, None)


@pytest.mark.asyncio
async def test_read_fields_no_live_session_errors():
    res = json.loads(await T.java_read_fields(cls="a.C", session_id=new_session_id()))
    assert res.get("error") is True


@pytest.mark.asyncio
async def test_capture_this_forwarded(monkeypatch):
    calls = {}
    def fake(script, cls, method, overload=None, capture_this=None):
        calls["args"] = (cls, method, overload, capture_this)
        return {"hook": f"{cls}.{method}", "since_seq": 3}
    sid = _sid()
    monkeypatch.setattr(java_mod, "java_hook", fake)
    try:
        res = json.loads(await T.java_hook(cls="a.C", method="decryptString",
                                           capture_this=["plainText"], session_id=sid))
        assert res.get("error") is not True, res
        assert calls["args"] == ("a.C", "decryptString", None, ["plainText"])
    finally:
        T.MANAGER._sessions.pop(sid, None)
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `PYTHONPATH=src python3 -m pytest tests/unit/test_java_object_state.py -q`
Expected: FAIL — `AttributeError: module 'pare_frida_mcp.tools' has no attribute 'java_read_fields'` (and the `capture_this` kwarg is rejected by the current `java_hook`).

- [ ] **Step 3: Add the `android/java.py` wrappers**

In `src/pare_frida_mcp/android/java.py`, extend `java_hook` and add `java_read_fields`:

```python
def java_hook(script, cls: str, method: str, overload: list | None = None,
              capture_this: list | None = None) -> dict:
    return script.exports_sync.java_hook_install(
        cls, method, overload or [], capture_this or [])


def java_read_fields(script, cls: str, fields: list | None = None) -> dict:
    return script.exports_sync.java_read_fields(cls, fields or [])
```

- [ ] **Step 4: Add the `tools.py` handler and extend `java_hook`**

In `src/pare_frida_mcp/tools.py`, change the `java_hook` signature to forward `capture_this` (the rest of the body is unchanged):

```python
async def java_hook(cls: str, method: str, overload: list | None = None,
                    capture_this: list | None = None, session_id: str = "") -> str:
    try:
        s = _resolve_session(session_id)
        res = java_mod.java_hook(s.script, cls, method, overload, capture_this)
        if isinstance(res, dict) and res.get("ambiguous"):
            return json.dumps({
                "summary": f"{cls}.{method} is overloaded - retry java_hook with "
                           f"'overload' set to one of these descriptor lists",
                "error": True, "overloads": res.get("overloads", [])})
        return _ok(f"hook installed: {cls}.{method}", hook=res)
    except Exception as e:
        return _err("java_hook failed", e)
```

Add the new handler (place it right after `java_hook`):

```python
async def java_read_fields(cls: str, fields: list | None = None,
                           session_id: str = "") -> str:
    try:
        s = _resolve_session(session_id)
        res = java_mod.java_read_fields(s.script, cls, fields)
        ic = res.get("instance_count", 0)
        instances = res.get("instances", [])
        statics = res.get("static_fields", {}) or {}
        note = " (capped)" if res.get("capped") else ""
        if ic == 0 and not statics:
            return _ok(
                f"no live instance of {cls} and no static value - trigger the "
                f"action then retry, or install java_hook with capture_this to "
                f"capture state at the call site",
                cls=cls, instance_count=0, instances=[], static_fields={})
        parts = []
        if ic:
            parts.append(f"{ic} instance(s) of {cls}"
                         + (" (multiple - ambiguous)" if ic > 1 else ""))
        if statics:
            parts.append(f"{len(statics)} static field(s)")
        summary = "; ".join(parts) + note
        # Fold a single string value inline so the model can succeed off the summary.
        if ic == 1 and len(instances[0].get("fields", {})) == 1:
            (fn, fv), = instances[0]["fields"].items()
            if isinstance(fv, str):
                summary += f'; {fn}="{fv[:120]}"'
        return _ok(summary, cls=cls, instance_count=ic,
                   instances=instances, static_fields=statics)
    except Exception as e:
        return _err("java_read_fields failed", e)
```

- [ ] **Step 5: Update the existing overload test's fake (now 4 args)**

In `tests/unit/test_java_hook_overload.py`, change the fake export signature and the assertion so it accepts the new `capture_this` positional:

```python
class _Exports:
    def __init__(self, result):
        self._result = result
        self.calls = []
    def java_hook_install(self, cls, method, overload, capture_this):
        self.calls.append((cls, method, overload, capture_this))
        return self._result
```

And in `test_overload_list_passed_through`, update the expected call to the 4-tuple:

```python
    assert T.MANAGER.get(sid).script.exports_sync.calls == [("C", "write", ["[B", "int", "int"], [])]
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `PYTHONPATH=src python3 -m pytest tests/unit/test_java_object_state.py tests/unit/test_java_hook_overload.py -q`
Expected: PASS (all).

- [ ] **Step 7: Commit**

```bash
git add src/pare_frida_mcp/android/java.py src/pare_frida_mcp/tools.py \
        tests/unit/test_java_object_state.py tests/unit/test_java_hook_overload.py
git commit -m "feat(tools): java_read_fields handler + capture_this forwarding"
```

---

### Task 2: Contract — declare the tool, widen the schema, fix the steering + count drift

**Files:**
- Modify: `src/pare_frida_mcp/contract.py` (add `java_read_fields` `ToolSpec`; add `capture_this` to `java_hook` schema; update `java_hook` / `read_hook_events` / `execute_script` descriptions)
- Modify: `tests/unit/test_contract.py` (count 18 → 19; new tier + description assertions)
- Modify: `tests/integration/test_server_list_tools.py` (replace the stale `== 15` magic count with an expected-name-set assertion)

**Interfaces:**
- Consumes: `tools.java_read_fields` from Task 1 (bound by name in `server.py:12-16` — the `ToolSpec.name` MUST be exactly `"java_read_fields"` or the server silently binds a stub).
- Produces: a 19-tool contract with `java_read_fields` at tier `high` and `java_hook` carrying an optional `capture_this` array.

- [ ] **Step 1: Write the failing contract tests**

In `tests/unit/test_contract.py`, replace `test_tool_count_is_18` and add the new assertions:

```python
def test_tool_count_is_19():
    # 18 (+ java_read_fields) -> 19
    assert len(TOOL_SPECS) == 19


def test_java_read_fields_is_high_tier():
    by_name = {s.name: s for s in TOOL_SPECS}
    assert by_name["java_read_fields"].risk_tier == "high"


def test_java_read_fields_description_leads_with_trigger():
    desc = {s.name: s for s in TOOL_SPECS}["java_read_fields"].description.lower()
    # steers the model from the stuck "ran but returned nothing" state to this tool
    assert "field" in desc
    assert "no re-trigger" in desc or "reads current" in desc
    assert "static" in desc


def test_java_hook_schema_and_description_cover_capture_this():
    spec = {s.name: s for s in TOOL_SPECS}["java_hook"]
    assert "capture_this" in spec.input_schema["properties"]
    desc = spec.description.lower()
    assert "capture_this" in desc
    # the widened-capture disclosure for the high-tier approver / audit log
    assert "object state" in desc or "widen" in desc


def test_read_hook_events_description_crosslinks_read_fields():
    desc = {s.name: s for s in TOOL_SPECS}["read_hook_events"].description.lower()
    assert "java_read_fields" in desc


def test_execute_script_redirect_includes_read_fields():
    desc = {s.name: s for s in TOOL_SPECS}["execute_script"].description
    assert "java_read_fields" in desc
```

In `tests/integration/test_server_list_tools.py`, replace the failing `== 15` test with an authoritative name-set (per the panel: prefer an expected-name-set over a magic number):

```python
from pare_frida_mcp.contract import TOOL_SPECS

EXPECTED_TOOLS = {
    "list_devices", "select_device", "attach", "list_sessions", "detach",
    "enumerate_processes", "enumerate_applications", "enumerate_modules",
    "enumerate_exports", "enumerate_classes", "enumerate_methods", "load_script",
    "execute_script", "java_hook", "java_hook_remove", "read_hook_events",
    "read_memory", "write_memory", "java_read_fields",
}


def test_tool_surface_matches_expected():
    assert {s.name for s in TOOL_SPECS} == EXPECTED_TOOLS
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `PYTHONPATH=src python3 -m pytest tests/unit/test_contract.py tests/integration/test_server_list_tools.py -q`
Expected: FAIL — `java_read_fields` absent from `TOOL_SPECS`, count is 18 not 19, `capture_this` not in the `java_hook` schema, cross-link strings missing.

- [ ] **Step 3: Add the `java_read_fields` ToolSpec**

In `src/pare_frida_mcp/contract.py`, add this entry to `TOOL_SPECS` immediately after the `java_hook` spec:

```python
    ToolSpec("java_read_fields", "high",
             "Read Java OBJECT STATE - the value of instance and/or static "
             "fields on a class - with no address needed. Use when a hook "
             "confirmed a method ran but its args/return were empty (a void "
             "method that stashes its result into a field), or when you need an "
             "object's state and have no native address (read_memory needs one "
             "you cannot get for a heap object). Reads CURRENT state now - no "
             "re-trigger needed (contrast java_hook capture_this, which snapshots "
             "at the NEXT call and needs a re-trigger). PREFER passing the field "
             "name(s) from static analysis; OMIT 'fields' to dump every declared "
             "field (instance and static) when you do not know the name. Instance "
             "values come back under instances[].fields, static values under "
             "static_fields (bounded: 10 instances, 64 fields). An EMPTY result "
             "means no live instance yet - trigger the action then retry, or use "
             "java_hook with capture_this. Omit session_id to target the "
             "most-recent live session.",
             _in(session_id={"type": "string"}, cls={"type": "string"},
                 fields={"type": "array", "items": {"type": "string"}})),
```

- [ ] **Step 4: Widen the `java_hook` spec (schema + description)**

Replace the existing `java_hook` `ToolSpec` in `contract.py` with this (adds the `capture_this` sentence to the description and the `capture_this` array to the schema):

```python
    ToolSpec("java_hook", "high",
             "Install an OBSERVING Java method hook (captures decoded arguments "
             "AND the return value; the original still runs). Works on app and "
             "framework classes. 'overload' is an ordered list of frida type "
             "descriptors, one per parameter (e.g. [\"[B\",\"int\",\"int\"]); "
             "omit it for a non-overloaded method - if the method is overloaded "
             "the call returns the available descriptor lists to choose from. "
             "Pass 'capture_this' (a list of field names) to ALSO snapshot those "
             "fields of 'this' AT the hook site, captured on the NEXT call (you "
             "must be able to re-trigger the action); if you have ALREADY "
             "triggered it, use java_read_fields instead. capture_this widens "
             "what this hook records from arguments/return to arbitrary named "
             "object state. Read what the hook captured with read_hook_events "
             "(start at the since_seq this call returns). WARNING: hooking an "
             "ultra-hot method (e.g. String.<init>) floods the buffer; a "
             "per-thread guard prevents recursion but the signal will be noisy.",
             _in(session_id={"type": "string"}, cls={"type": "string"},
                 method={"type": "string"},
                 overload={"type": "array", "items": {"type": "string"}},
                 capture_this={"type": "array", "items": {"type": "string"}})),
```

- [ ] **Step 5: Add the `read_hook_events` cross-link and the `execute_script` redirect**

In `contract.py`, in the `read_hook_events` description, insert this sentence right after "An EMPTY result means the hooked action has not been triggered yet - retry after the app action, do not remove the hook.":

```
A NON-EMPTY event whose ret is null means the method ran but returned nothing - read the resulting object state with java_read_fields.
```

In the `execute_script` description, change the redirect list from:

```
For Java work use enumerate_classes / enumerate_methods / java_hook instead,
```

to:

```
For Java work use enumerate_classes / enumerate_methods / java_hook / java_read_fields instead,
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `PYTHONPATH=src python3 -m pytest tests/unit/test_contract.py tests/integration/test_server_list_tools.py -q`
Expected: PASS (all).

- [ ] **Step 7: Commit**

```bash
git add src/pare_frida_mcp/contract.py tests/unit/test_contract.py \
        tests/integration/test_server_list_tools.py
git commit -m "feat(contract): declare java_read_fields (high) + capture_this; fix tool-count drift"
```

---

### Task 3: Bundled agent — `resolveField`, `javaReadFields`, `capture_this` capture

**Files:**
- Modify: `agent/src/index.ts` (add `resolveField`; add `javaReadFields` rpc export; capture `this` in `installOn`; thread `captureThis` through `javaHookInstall`)
- Modify (generated): `agent/dist/agent.js` (via `npm run build`)

**Interfaces:**
- Consumes: the existing `describe()` (`index.ts:34`), the `active` reentrancy set (`index.ts:5`), and `frida-java-bridge` `Java` (`index.ts:1`).
- Produces: `rpc.exports.javaReadFields(cls, fields?)` (Python side: `exports_sync.java_read_fields`, called by Task 1's wrapper) and `javaHookInstall(cls, method, overload?, captureThis?)` (Python side: `java_hook_install`, called by Task 1's wrapper). Return shape of `javaReadFields`: `{cls, instance_count, instances:[{fields:{}}], static_fields:{}, capped}`.

> **Note on testing:** the TypeScript exports need the Frida runtime + a live VM and cannot be unit-tested in this repo (same posture as `enumerate_methods` — see the spec's Testing section). This task's automated gate is a successful build; behavioral verification is Task 4's live acceptance.

- [ ] **Step 1: Add the shared `resolveField` helper**

In `agent/src/index.ts`, add after `describe()` (around line 50):

```ts
// A frida-java-bridge field wrapper exposes a `value` getter; a method wrapper
// does not. When a field name collides with a same-named method, the bridge
// remaps the field to a suffixed accessor `_<name>`, so a raw-name read would
// resolve to the METHOD wrapper (value === undefined). Resolve to a real field.
function isFieldWrapper(w: any): boolean {
  return w != null && typeof w === "object" && "value" in w;
}
function resolveField(holder: any, name: string): { found: boolean; wrapper?: any } {
  let w = holder[name];
  if (isFieldWrapper(w)) return { found: true, wrapper: w };
  w = holder["_" + name];                       // bridge collision spelling
  if (isFieldWrapper(w)) return { found: true, wrapper: w };
  return { found: false };
}
```

- [ ] **Step 2: Add the `javaReadFields` rpc export**

In `agent/src/index.ts`, add this export inside `rpc.exports` (e.g. right after `javaEnumerateMethods`):

```ts
  javaReadFields(cls: string, fields?: string[]) {
    const out: any = { cls, instance_count: 0, instances: [], static_fields: {}, capped: false };
    Java.perform(() => {
      const klass: any = Java.use(cls);                 // throws if class not loaded -> caught by handler
      const Modifier: any = Java.use("java.lang.reflect.Modifier");
      const wanted: string[] = (fields && fields.length)
        ? fields
        : klass.class.getDeclaredFields().map((f: any) => f.getName());
      const MAX_INSTANCES = 10, MAX_FIELDS = 64;
      const names = wanted.slice(0, MAX_FIELDS);
      if (wanted.length > names.length) out.capped = true;

      // Partition by the field's OWN modifier, not by instance count.
      const staticNames: string[] = [], instanceNames: string[] = [];
      for (const n of names) {
        try {
          const f = klass.class.getDeclaredField(n);
          (Modifier.isStatic(f.getModifiers()) ? staticNames : instanceNames).push(n);
        } catch (e) { instanceNames.push(n); }   // not declared here -> resolver reports not-found
      }

      // Static fields: read once off the class wrapper, no instance needed.
      for (const n of staticNames) {
        try {
          const acc = resolveField(klass, n);
          out.static_fields[n] = acc.found ? describe(acc.wrapper.value) : { error: "field not found" };
        } catch (e: any) { out.static_fields[n] = { error: String(e) }; }
      }

      // Instance fields: read off each live instance.
      if (instanceNames.length) Java.choose(cls, {
        onMatch(inst: any) {
          if (out.instances.length >= MAX_INSTANCES) { out.capped = true; return; }
          const fv: any = {};
          for (const n of instanceNames) {
            try {
              const acc = resolveField(inst, n);
              fv[n] = acc.found ? describe(acc.wrapper.value) : { error: "field not found" };
            } catch (e: any) { fv[n] = { error: String(e) }; }
          }
          out.instances.push({ fields: fv });
        },
        onComplete() {},
      });
      out.instance_count = out.instances.length;
    });
    return out;
  },
```

- [ ] **Step 3: Thread `captureThis` through `javaHookInstall` and capture on the non-throw path**

In `agent/src/index.ts`, change the `javaHookInstall` signature to accept the new parameter:

```ts
  javaHookInstall(cls: string, method: string, overload?: any[], captureThis?: string[]) {
```

Then, inside `installOn`, replace the body of `target.implementation` with this version (adds `thisD`, the capture block inside the same `active`-guard bracket as `retD`, and conditionally attaches `this` to the event so events stay byte-identical when `captureThis` is empty):

```ts
        target.implementation = function (...args: any[]) {
          const tid = Process.getCurrentThreadId();
          if (active.has(tid)) {
            send({ hook: true, seq: ++SEQ, class: cls, method, overload: ov, reentrant: true, thread: tid });
            return target.apply(this, args);
          }
          active.add(tid);
          let argsD: any;
          try { argsD = args.map(describe); } finally { active.delete(tid); }
          let retD: any = null, threw = false, thisD: any = null;
          try {
            const r = target.apply(this, args);          // original runs with the guard released
            active.add(tid);
            try {
              retD = describe(r);
              if (captureThis && captureThis.length) {   // same guard bracket as retD
                thisD = {};
                for (const n of captureThis) {
                  try {
                    const acc = resolveField(this, n);
                    thisD[n] = acc.found ? describe(acc.wrapper.value) : { error: "field not found" };
                  } catch (e: any) { thisD[n] = { error: String(e) }; }
                }
              }
            } finally { active.delete(tid); }
            return r;
          } catch (e: any) {
            threw = true; retD = { error: String(e) };   // capture_this NOT read on the throw path
            throw e;
          } finally {
            const ev: any = { hook: true, seq: ++SEQ, class: cls, method, overload: ov,
                              args: argsD, ret: retD, threw, thread: tid };
            if (thisD !== null) ev.this = thisD;         // only present when captured
            send(ev);
          }
        };
```

- [ ] **Step 4: Rebuild the bundle**

Run: `cd agent && npm run build && cd ..`
Expected: build succeeds, no TypeScript errors, `agent/dist/agent.js` is regenerated.

- [ ] **Step 5: Verify the exports made it into the bundle**

Run: `grep -c "javaReadFields\|captureThis\|resolveField" agent/dist/agent.js`
Expected: a non-zero count (the identifiers survive `frida-compile`, which does not mangle rpc export keys).

- [ ] **Step 6: Run the full unit + integration suite (no regressions)**

Run: `PYTHONPATH=src python3 -m pytest tests/unit tests/integration -q`
Expected: PASS (all) — the Python layer is unchanged since Task 2; this confirms the agent edit broke nothing importable.

- [ ] **Step 7: Commit (source + generated bundle together)**

```bash
git add agent/src/index.ts agent/dist/agent.js
git commit -m "feat(agent): javaReadFields export + capture_this hook capture (collision-safe, guarded)"
```

---

### Task 4: Live acceptance — the OMTG_DATAST_011_Memory falsification

**Files:**
- Modify: `tests/device/test_android_flows.py` (add device acceptance tests, guarded to skip when the OMTG app / trigger is unavailable)

**Interfaces:**
- Consumes: a running `emulator-5554` with `sg.vp.owasp_mobile.omtg_android` installed, and an operator to drive the UI (PARE is a co-pilot; the operator owns triggering). Reuses the device fixtures in `tests/device/conftest.py` and the attach/hook flow from the existing tests in this file.
- Produces: end-to-end confirmation that the root-cause is closed (`plainText` retrieved in one `java_read_fields` call).

> **Note:** these require live hardware and human UI interaction, so they are not CI-gated; they are the acceptance script the implementer (or Shane) runs against the emulator. Each guards on availability and `pytest.skip`s cleanly so the file still collects in CI.

- [ ] **Step 1: Add the acceptance tests**

Append to `tests/device/test_android_flows.py`:

```python
OMTG_APP = "sg.vp.owasp_mobile.omtg_android"
OMTG_MEM = "sg.vp.owasp_mobile.OMTG_Android.OMTG_DATAST_011_Memory"


async def _attach_omtg():
    res = json.loads(await T.attach(target=OMTG_APP))
    if "session_id" not in res:
        pytest.skip(f"OMTG app not attachable: {res.get('summary')}")
    return res["session_id"]


@pytest.mark.asyncio
async def test_read_fields_recovers_plaintext_in_one_call():
    """Root-cause falsification: after the operator triggers decryptString on the
    OMTG_DATAST_011_Memory screen, one java_read_fields call returns plainText."""
    sid = await _attach_omtg()
    try:
        input(f"\n[operator] open '{OMTG_MEM}' in the app, then press Enter...")
        doc = json.loads(await T.java_read_fields(cls=OMTG_MEM, fields=["plainText"], session_id=sid))
        assert doc.get("error") is not True, doc
        vals = [i["fields"].get("plainText") for i in doc.get("instances", [])]
        assert any(isinstance(v, str) and v for v in vals), doc     # non-empty plaintext recovered
    finally:
        T.MANAGER.get(sid).frida_session.detach()


@pytest.mark.asyncio
async def test_read_fields_dump_all_finds_plaintext():
    """Omitting fields dumps declared fields; plainText appears among them."""
    sid = await _attach_omtg()
    try:
        input(f"\n[operator] open '{OMTG_MEM}' in the app, then press Enter...")
        doc = json.loads(await T.java_read_fields(cls=OMTG_MEM, session_id=sid))
        assert doc.get("error") is not True, doc
        assert any("plainText" in i.get("fields", {}) for i in doc.get("instances", [])), doc
    finally:
        T.MANAGER.get(sid).frida_session.detach()


@pytest.mark.asyncio
async def test_capture_this_snapshots_plaintext_at_hook_site():
    """capture_this on decryptString surfaces this.plainText via read_hook_events."""
    sid = await _attach_omtg()
    try:
        hook = json.loads(await T.java_hook(cls=OMTG_MEM, method="decryptString",
                                            capture_this=["plainText"], session_id=sid))
        assert hook.get("hook"), hook
        input(f"\n[operator] open '{OMTG_MEM}' to trigger decryptString, then press Enter...")
        ev = json.loads(await T.read_hook_events(since_seq=0, session_id=sid))
        thises = [e.get("this", {}).get("plainText") for e in ev.get("events", [])]
        assert any(isinstance(v, str) and v for v in thises), ev
    finally:
        T.MANAGER.get(sid).frida_session.detach()
```

- [ ] **Step 2: Run the acceptance suite against the emulator (operator-in-the-loop)**

Run: `PYTHONPATH=src python3 -m pytest tests/device/test_android_flows.py -q -s -k "read_fields or capture_this"`
(The `-s` flag lets the `input()` operator prompts through.)
Expected: with the emulator up and OMTG installed, all three PASS — `plainText` recovered by the pull (`java_read_fields`), by dump-all, and by the push (`capture_this`). Without the emulator/app, they `skip`, and the file still collects.

- [ ] **Step 3: Manually spot-check the collision + static edges (no dedicated OMTG target)**

OMTG_011's `plainText` is a clean instance field, so the collision and static paths have no OMTG target. Verify them opportunistically against any loaded class that has (a) a field shadowed by a same-named method, and (b) a static field, using `java_read_fields(<cls>, ["<name>"])` and confirming the value comes back (not `null`, not `{error}`) under `instances[].fields` / `static_fields` respectively. Record the classes used in the PR description. (A dedicated fixture APK is the clean long-term home — deferred with the static-enumeration tool.)

- [ ] **Step 4: Commit**

```bash
git add tests/device/test_android_flows.py
git commit -m "test(device): OMTG_011 acceptance for java_read_fields + capture_this"
```

---

## Self-Review

**Spec coverage** — every spec section maps to a task:
- `java_read_fields` (agent export) → Task 3 Step 2; (handler) → Task 1 Step 4; (ToolSpec/tier) → Task 2 Step 3.
- `capture_this` (agent) → Task 3 Step 3; (forwarding) → Task 1 Steps 3-4; (schema/desc) → Task 2 Step 4.
- Shared collision-safe `resolveField` → Task 3 Step 1.
- Modifier-driven static/instance dispatch → Task 3 Step 2.
- Steering (trigger wording, A/C directional, `ret:null` cross-link, `execute_script` redirect) → Task 2 Steps 3-5.
- Risk tiers → Task 2 (asserted Steps 1/3/4).
- Bounding (10 inst / 64 fields / CAP / capped-in-summary) → Task 3 Step 2 + Task 1 Step 4.
- Envelope (`instances[].fields` + `static_fields`, inline-value summary) → Task 1 Step 4.
- Tool-count drift reconciliation → Task 2 Step 1.
- Handler-name-vs-ToolSpec-name binding safety → Task 2 (name-set test) + Task 1 (handler exists).
- Testing (unit fakes, contract, device acceptance incl. collision + static) → Tasks 1, 2, 4.
- Deferred items (raw heap dump, static field *enumeration*) → out of scope, no task, by design.

**Placeholder scan:** none — every code step carries complete code; every run step carries an exact command + expected result.

**Type consistency:** `java_read_fields` return keys (`cls, instance_count, instances, static_fields, capped`) are identical across Task 3 (producer), Task 1 (consumer/handler + tests), and Task 4 (asserts `instances[].fields`, `static_fields`). `java_hook`/`java_hook_install` carry `capture_this`/`captureThis` consistently across Tasks 1 (Python) and 3 (JS). Hook-event `this` key is written in Task 3 Step 3 and read in Task 4 Step 1. `resolveField` returns `{found, wrapper}` in Task 3 Step 1 and is consumed with that shape in Steps 2-3.
