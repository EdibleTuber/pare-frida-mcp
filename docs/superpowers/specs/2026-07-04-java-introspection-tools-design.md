# Java Introspection Tools (enumerate_classes / enumerate_methods) — Design

**Date:** 2026-07-04
**Repo:** pare-frida-mcp
**Status:** Approved — ready for implementation plan.

## Goal

Give the model two bounded, read-only Java introspection tools —
`enumerate_classes` and `enumerate_methods` — so it can discover a target app's
classes and a class's methods through **deterministic tool calls** instead of
hand-writing fragile Frida JS through the `critical` `execute_script` gate.

## Why

A manual test run against the live OMTG target (`sg.vp.owasp_mobile.omtg_android`)
showed the model asked to "enumerate the methods of the app" and failed: it fell
back to `execute_script` with hand-written `Java.perform` scripts, which on
Frida 17 throw `ReferenceError: 'Java' is not defined` (a bare ad-hoc script has
no Java bridge). It hit the `critical` approval gate three times and gave up.

The capability to do this correctly **already exists** in the bundled agent
(`agent/src/index.ts`): it imports `frida-java-bridge` and exposes a working
`javaEnumerate(filter)` rpc export. That export was simply never surfaced as an
MCP tool. This design surfaces it and adds the symmetric methods export.

This is lever 1 ("push reasoning into deterministic tools") from the
local-above-class strategy: the model interprets pre-digested structure instead
of writing introspection code.

## Scope

**In:** `enumerate_classes`, `enumerate_methods`.
**Out (deferred):** `enumerate_fields`; operator fast-path `/classes` `/methods`
(cheap `_EnumView` tail, later); static/all-classes discovery (that is the
existing `static_analyze` pipeline's job — do not duplicate it).

## Design

### Class discovery: loaded-only (dynamic)

`enumerate_classes` lists classes the ART runtime has **actually loaded**, via
the existing `javaEnumerate` export (`Java.enumerateLoadedClassesSync`, filtered
by substring, capped at 500). This matches the Frida workflow: you attach,
navigate into the screen you care about, then enumerate. OMTG lazy-loads each
challenge's classes on entry — so a challenge's classes appear only once you are
in it. This is expected behavior, documented in the tool description, not a bug.
Exhaustive/offline discovery is out of scope (see above).

### Components (three files)

All introspection runs on the **bundled-agent rpc path** — the same
`s.script.exports_sync.<name>()` wiring `enumerate_modules` and `java_hook`
already use. The bundled agent imports the Java bridge, which is why this works
where a bare `execute_script` cannot.

**1. `agent/src/index.ts`** — `javaEnumerate` (classes) already exists. Add one
export, then recompile the bundle:

```ts
javaEnumerateMethods(cls: string) {
  const out: { name: string; signature: string }[] = [];
  Java.perform(() => {
    const klass = Java.use(cls);                 // loads the class on demand
    klass.class.getDeclaredMethods()
      .forEach((m: any) => out.push({ name: m.getName(), signature: m.toString() }));
  });
  return out;
}
```

Recompile: `npm run build` in `agent/`
(`frida-compile src/index.ts -o dist/agent.js -c`).

`Java.use(cls)` loads the class on demand, so `enumerate_methods` resolves a
class that exists even if it was not already loaded — but the class must exist
(a nonexistent name throws; see Error handling). `Java.use` triggers class
*loading* (a wrapper), not static *initialization* (`<clinit>`), so the tool
stays effectively read-only (tier `low` holds).

`getDeclaredMethods()` is **declared-only** by design — it excludes inherited
framework methods (`Object`/`Activity`/…). This is intentional: RE targets the
app's own logic, not framework noise. Inherited-method enumeration is not a goal.

**2. `src/pare_frida_mcp/tools.py`** — two async tools. Frida snake-cases rpc
export names on the Python side (existing precedent: `exports_sync.java_hook_remove`),
so `javaEnumerate` → `java_enumerate`, `javaEnumerateMethods` →
`java_enumerate_methods`:

```python
async def enumerate_classes(session_id: str, filter: str = "") -> str:
    try:
        sid = validate_session_id(session_id)
        s = MANAGER.get(sid)
        rows = s.script.exports_sync.java_enumerate(filter)
        return _ok(f"{len(rows)} classes", classes=rows)
    except Exception as e:
        return _err("enumerate_classes failed", e)

async def enumerate_methods(session_id: str, cls: str) -> str:
    try:
        sid = validate_session_id(session_id)
        s = MANAGER.get(sid)
        rows = s.script.exports_sync.java_enumerate_methods(cls)
        return _ok(f"{len(rows)} methods for {cls}", methods=rows)
    except Exception as e:
        return _err("enumerate_methods failed", e)
```

**3. `src/pare_frida_mcp/contract.py`** — two `ToolSpec` entries at tier `low`.

### Envelope

- `enumerate_classes` → `{"summary": "<n> classes", "classes": ["<fqcn>", ...]}`
- `enumerate_methods` → `{"summary": "<n> methods for <cls>",
  "methods": [{"name": "<methodName>", "signature": "<java descriptor>"}, ...]}`

Matches `enumerate_modules`/`enumerate_exports` so capture-at-wire, `/snapshot`,
and a future operator view all consume a uniform `{summary, <plural>:[rows]}`
shape. `signature` carries the full Java descriptor (return + parameter types) —
exactly what `java_hook` needs for overload resolution, so methods → hooks flows
without a second lookup.

### Risk tier: `low`

Pure read-only introspection — no memory writes, no code execution, cannot
change target state. Distinct from `execute_script` (stays `critical`). This is
the tier granularity the test run exposed as wrong: the model was paying
`critical` to list classes.

### Error handling

`enumerate_methods` on a nonexistent class → `Java.use` throws → the standard
`_err("enumerate_methods failed", e)` wrapper surfaces the failure (honest, not a
silent empty list). Same pattern as every other tool. An unknown `session_id`
is caught by `validate_session_id` → `_err`.

### Bounding

`java_enumerate` caps classes at 500 and takes a substring filter.
`enumerate_methods` returns declared-only methods for a single class (bounded;
KeyStore = 5). The capture layer bounds anything large at the wire regardless.

## Testing

- **Unit** (match `tests/unit/test_tools_enum.py`): fake session whose
  `script.exports_sync.java_enumerate` / `java_enumerate_methods` return canned
  lists → assert envelope shape + summary for both tools; assert the `_err` path
  on a raised exception.
- **Contract** (`tests/unit/test_contract.py`): both tools present at tier `low`.
- **Live acceptance:**
  `enumerate_methods("sg.vp.owasp_mobile.OMTG_Android.OMTG_DATAST_001_KeyStore")`
  returns the 4 declared methods `createNewKeys`, `encryptString`,
  `decryptString`, `onCreate` with signatures. `getDeclaredMethods()` excludes
  the `<init>` constructor by design (constructors are a separate reflection
  category); constructor enumeration is deferred like fields.

**Stated gap:** the TypeScript export itself cannot be cleanly unit-tested (it
needs the Frida runtime + a live VM). It is covered by the live acceptance test,
not by unit tests.

## Acceptance criteria

1. `enumerate_classes(filter="OMTG")` on the KeyStore screen lists the loaded
   OMTG classes.
2. `enumerate_methods(<KeyStore fqcn>)` returns the 4 declared methods
   (`createNewKeys`, `encryptString`, `decryptString`, `onCreate`) with
   signatures; the `<init>` constructor is excluded by `getDeclaredMethods`.
3. Both tools are tier `low`; `execute_script` remains `critical`.
4. Full unit suite green; no regression to existing tools.
