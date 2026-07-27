# Java Object-State Reads (`java_read_fields` + `capture_this`) — Design

**Date:** 2026-07-22
**Repo:** pare-frida-mcp
**Status:** Approved — ready for implementation plan.

## Goal

Give the model a way to read **Java object state** — the value of an instance
field, on demand or at a hook site — so it can recover a secret that a method
computes into a field rather than returns. Two additions:

- **A — `java_read_fields(cls, fields?)`**: a new tool. Read named instance
  fields off live instances of a class (a *pull*, no re-trigger needed).
- **C — `capture_this` on `java_hook`**: a new optional parameter. Snapshot named
  fields of `this` at the hook site, the instant the method runs (a *push*).

## Why

A live test run on `OMTG_DATAST_011_Memory` stalled the model for ~8 turns. The
target's `public void decryptString()` takes no args, returns `void`, and stashes
the plaintext into the instance field `plainText` (visible statically:
`iput-object v0, … ->plainText Ljava/lang/String;`). So `java_hook` on it captures
`{args:[], ret:null}` — it confirms the method *ran* and reveals nothing.

The model's correct instinct — `Java.choose(cls){ onMatch: o => o.plainText.value }`
— is impossible through `execute_script`: Frida 17 removed the `Java` global from
bare scripts (`core/scripts.py:29-33`), so any `Java.*` reference throws
`ReferenceError`. `read_memory` needs a native address the model cannot obtain for
a Java heap object. The whole "decrypt-into-a-field" class of targets therefore
had **no tool path**, and the model thrashed rediscovering that hole.

Both fixes live where Java work belongs: the bundled agent
(`agent/src/index.ts`), which imports `frida-java-bridge` and already runs
`Java.perform`. This is the same "push reasoning into deterministic tools" lever
that `enumerate_classes`/`enumerate_methods` and `java_hook` sit on.

The field name itself is **not** a discovery problem in the normal flow: PARE's
static worker already surfaces it. In the motivating transcript the model read
`plainText` from `static_grep_smali` before ever touching the device. So the
recommended input is an explicit field-name list sourced from static analysis;
the omit-fields dump-all path (below) is a bounded fallback for when static can't
(obfuscation / R8 renaming).

## Scope

**In:** `java_read_fields` (tool A), reading **both instance and static fields**
via modifier-driven dispatch (below); `capture_this` parameter on `java_hook`
(part C); the shared collision-safe field-accessor resolution both need; the
steering/wording changes that stop the model thrashing between A and C.

**Out (deferred, with rationale):**

- **Raw heap dump + string scan** (`scan_memory`, still `NotImplementedError` in
  `core/memory.py:20`, unexposed — no `ToolSpec`, no handler). The blind escape
  hatch for when the class/field is unknown; it needs the snapshot/capture layer
  and produces high-noise blobs. Typed object reads (A/C) do not foreclose it —
  they are complementary. Deferred.
- **Static field enumeration** (a `static_list_fields`-style tool in the apk_re
  direction). The eventual clean home for field *discovery* against obfuscated
  targets — enumerate a class's fields+types offline, no device. Out of this pass.

## Design

Both A and C reuse the existing `describe()` serializer (`index.ts:34`), so a
`String` field decodes to clipped text, a `byte[]` field to `{hex, utf8, len}`,
and `null` to `null` — identical to how `java_hook` decodes args/return, so the
model consumes field values with a mental model it already has.

### Shared: collision-safe field-accessor resolution

frida-java-bridge does **not** always expose a field under its raw name. When a
field name collides with a same-named method, the field is remapped to a mangled
accessor (e.g. `plainText` → `_plainText` / `plainText_field`, per the bridge's
collision rule) and `wrapper[rawName]` resolves to the **method** wrapper, whose
`.value` is `undefined`. Reading by raw name would then silently return `null`.
OMTG_011 passes only because `plainText` collides with nothing.

A shared helper resolves each requested name to a real field accessor:

- Prefer `wrapper[name]` when it is a field wrapper (has a `.value` getter).
- Otherwise probe the bridge's known mangled spelling(s) for `name`.
- If neither resolves to a field, report the name as **not-found** (distinct from
  a field whose value is genuinely `null`).

For the dump-all path (below), enumerate via `klass.class.getDeclaredFields()`,
map each name through the same resolution, and **skip** any that resolve to a
method wrapper rather than a field.

### A — `java_read_fields(cls, fields?, session_id?)`

Runs on the bundled-agent rpc path (`s.script.exports_sync.<name>()`), same wiring
as `java_hook`/`enumerate_methods`.

**Agent export** (`agent/src/index.ts`), recompiled with `npm run build`:

```ts
javaReadFields(cls: string, fields?: string[]) {
  const out: any = { cls, instance_count: 0, instances: [], static_fields: {}, capped: false };
  Java.perform(() => {
    const klass: any = Java.use(cls);                 // throws if class not loaded → caught
    const Modifier: any = Java.use("java.lang.reflect.Modifier");
    const wanted = (fields && fields.length)
      ? fields
      : klass.class.getDeclaredFields().map((f: any) => f.getName());  // dump-all path
    const MAX_INSTANCES = 10, MAX_FIELDS = 64;
    const names = wanted.slice(0, MAX_FIELDS);
    if (wanted.length > names.length) out.capped = true;

    // Partition by the field's OWN modifier, not by instance count.
    const staticNames: string[] = [], instanceNames: string[] = [];
    for (const n of names) {
      try {
        const f = klass.class.getDeclaredField(n);
        (Modifier.isStatic(f.getModifiers()) ? staticNames : instanceNames).push(n);
      } catch (e) { instanceNames.push(n); }   // not declared here → resolver reports not-found
    }

    // Static fields: read once off the class wrapper, no instance needed.
    for (const n of staticNames) {
      try { const acc = resolveField(klass, n);
            out.static_fields[n] = acc.found ? describe(acc.wrapper.value) : { error: "field not found" }; }
      catch (e: any) { out.static_fields[n] = { error: String(e) }; }
    }

    // Instance fields: read off each live instance.
    if (instanceNames.length) Java.choose(cls, {
      onMatch(inst: any) {
        if (out.instances.length >= MAX_INSTANCES) { out.capped = true; return; }
        const fv: any = {};
        for (const n of instanceNames) {
          try { const acc = resolveField(inst, n);   // shared collision-safe resolver
                fv[n] = acc.found ? describe(acc.wrapper.value) : { error: "field not found" }; }
          catch (e: any) { fv[n] = { error: String(e) }; }   // per-field, never aborts batch
        }
        out.instances.push({ fields: fv });
      },
      onComplete() {},
    });
    out.instance_count = out.instances.length;
  });
  return out;
}
```

Key properties, each answering a panel finding:

- **Static vs instance is decided by the field's declared modifier**
  (`java.lang.reflect.Modifier.isStatic`, via `getDeclaredField`), not guessed from
  instance count. Static fields are read once off the class wrapper (the correct
  receiver for a static) and returned under `static_fields`; instance fields are
  read off live instances under `instances[].fields`. This handles a class holding
  *both*, in one call. It deliberately does **not** use the rejected
  "fall back to static when `Java.choose` finds nothing" design — that guessed from
  the wrong signal and mis-read instance names through the class wrapper (which
  throws).
- **Per-field try/catch.** A wrong/mangled/missing name yields
  `{error: …}` for *that field only* — it never throws out of the loop and aborts
  the whole read (the unguarded `inst[f].value` in the naive version does).
- **Value vs null vs not-found are distinct.** `null` = field is null;
  `{error:"field not found"}` = name did not resolve to a field. The model can
  tell "not triggered yet" from "wrong name."
- **Explicit `fields` is the recommended input**; omit `fields` → dump every
  declared field (bounded, below). Description foregrounds: *pass names from static
  analysis; omit only when you do not know them.*
- **Empty/ambiguous result → guidance, not silence.** When instance fields were
  requested and `instance_count == 0` (activity GC'd / not yet created / action not
  triggered), or every field is `null`, the handler's summary steers: *"no live
  instance / no value yet — trigger the action then retry, or install `java_hook`
  with `capture_this` to grab state at the call site."* `instance_count > 1` is
  flagged ambiguous in the summary. (Static-only reads need no live instance, so
  `instance_count == 0` is not an error when only static fields were requested.)
- **Class-not-loaded** (`Java.use`/`Java.choose` throw `ClassNotFoundError`) is
  caught and surfaced with the *"navigate into the screen/activity first"* hint,
  same as `enumerate_classes` (`contract.py:66-70`).

The return shape is the single invariant
`{cls, instance_count, instances:[{fields}], static_fields:{}, capped}`. Instance
and static values live under separate keys because static-vs-instance is a **fixed
property of the field**, not a runtime condition — so this is honest structure,
not the conditional-shape footgun the panel flagged (the same logical value moving
between keys depending on runtime state).

**Caveat — reading a static field can trigger `<clinit>`.** `Java.use(cls)` loads
the class (a wrapper) without static-initializing it, but *reading* a static field
forces class initialization if it has not run. In the normal flow the class has
already been exercised, so `<clinit>` already ran and the read is inert; the tier
stays `high` regardless. Noted so the (small) non-read-only edge is a decision, not
a surprise.

**Plumbing** (mirrors `enumerate_methods`, snake-cased on the Python side):

- `android/java.py`: `def java_read_fields(script, cls, fields): return
  script.exports_sync.java_read_fields(cls, fields or [])`.
- `tools.py`: `async def java_read_fields(cls, fields=None, session_id="")` →
  resolve session → call → `_ok(summary, cls=…, instance_count=…, instances=…)`;
  `_err` on exception. **The handler name must be byte-identical to the `ToolSpec`
  name** — `server.py:12-16` binds by `getattr` and silently falls back to a stub
  on a miss (covered by a handler test, below).
- `contract.py`: one `ToolSpec("java_read_fields", "high", …)`.

### C — `capture_this` on `java_hook`

New optional parameter `capture_this: string[]` (field names). When present, the
hook body reads those fields off `this` **after** the original runs and adds them
to the emitted event; when absent, behavior is byte-identical to today (no
`this` capture), preserving noise control and backward compatibility.

Placement inside the existing hook body (`index.ts:99-127`), non-throw path only:

```ts
try {
  const r = target.apply(this, args);        // original runs, guard released
  active.add(tid);
  try {
    retD = describe(r);
    if (captureThis && captureThis.length) {  // ← new: same guard bracket as retD
      thisD = {};
      for (const n of captureThis) {
        try { const acc = resolveField(this, n);
              thisD[n] = acc.found ? describe(acc.wrapper.value) : { error: "field not found" }; }
        catch (e) { thisD[n] = { error: String(e) }; }
      }
    }
  } finally { active.delete(tid); }
  return r;
} catch (e) { threw = true; retD = { error: String(e) }; throw e; }
finally {
  send({ hook: true, seq: ++SEQ, class: cls, method, overload: ov,
         args: argsD, ret: retD, this: thisD, threw, thread: tid });
}
```

- **Reentrancy bracket.** The `this`-field `describe()` calls run inside the same
  `active.add(tid)/active.delete(tid)` bracket that wraps `retD` (`index.ts:117-118`),
  because `describe()` → `toString()` can re-enter a hooked method. Without the
  bracket a hooked `toString`/getter would recurse.
- **Non-throw path only.** Fields are captured after a successful `apply`; on the
  throw path `this` may be half-mutated and a field read could itself throw and
  mask the original exception. `capture_this` is not read when the target threw.
- **Explicit name list** (not a dump-all switch): keeps the widened capture
  visible to the approver and the audit log (see Risk tier). The dump-all
  discovery affordance lives on A, so no Java-state path is strictly name-gated.
- Flows out through `read_hook_events` unchanged, under the `this` key.

### Steering (stops A↔C thrashing and connects the stuck state to the fix)

These description changes are load-bearing, not polish — the whole design exists
to end an 8-turn stall whose hinge was "hook confirmed execution but `ret` was
null," and nothing currently points the model from there to the new tools.

- **`java_read_fields` description leads with the trigger** in the model's own
  words: *"Use when a hook confirmed a method ran but its args/return were empty (a
  void method that stashes its result into a field), or when you need a Java
  object's state and have no address for it. Reads current state now — no
  re-trigger needed. Prefer passing the field name(s) from static analysis; omit
  `fields` to dump every declared field (instance and static) when you don't know
  the name."*
- **`read_hook_events` gets a cross-link** (`contract.py:117-128`): *"A non-empty
  event with `ret:null` means the method ran but returned nothing — read the
  resulting object state with `java_read_fields`."* (Its existing text only covers
  the *empty* result case.)
- **`capture_this` on `java_hook` is directional**: *"Snapshot named fields of
  `this` AFTER the method runs; captured at the NEXT call, so you must be able to
  re-trigger the action. If you have ALREADY triggered it, use `java_read_fields`
  instead — no re-trigger needed."*
- **`java_hook` description discloses the widened capture** (`contract.py:98-108`):
  it currently advertises only "decoded arguments AND the return value";
  `capture_this` lets one high-tier approval also exfiltrate arbitrary named object
  state, which the approver and audit log must see.
- **`execute_script` redirect list** (`contract.py:87-89`) adds `java_read_fields`
  so a model reasoning toward the Java-blind escape hatch for state inspection is
  pointed at the tool that now solves it.

## Envelope

- `java_read_fields` → `{"summary": "<n> instance(s) of <cls>[; <field>=\"…\"][ (capped)]",
  "cls": "<fqcn>", "instance_count": <n>, "instances": [{"fields": {"<name>": <described>}}],
  "static_fields": {"<name>": <described>}}`. Instance-field values live under
  `instances[].fields`; static-field values under `static_fields` (empty `{}` when
  none requested/static). The summary folds the found value inline (`_ok`
  convention, `tools.py:26-29`; cf. `enumerate_classes` cap-in-summary at
  `tools.py:184`) so the model can succeed off the summary without indexing the
  array in the common single-instance case.
- `java_hook` events (via `read_hook_events`) gain an optional `this` key:
  `{… "args": […], "ret": …, "this": {"<name>": <described>}, "threw": …}`. Absent
  when `capture_this` was not passed.

## Risk tier

- **`java_read_fields` = `high`.** Reads potentially-sensitive decrypted app state.
  Sits alongside `read_memory` (high) and `java_hook` (high), and is *narrower*
  than `read_memory` (which reads any address); well below `execute_script`
  (critical). Read-only, so not critical. **Confirmed by the security panel — do
  not inflate to critical.**
- **`java_hook` stays `high`; `read_hook_events` stays `low`.** `capture_this` is
  armed only through the high-tier `java_hook` install, so the low-tier
  `read_hook_events` replaying it is the same already-accepted model documented at
  `contract.py:117-126` (non-destructive buffer replay behind a high-tier install),
  not a gating bypass. The audit pipeline records the `java_hook` install call
  (with its `capture_this` args) as the gated event.

## Error handling

- Per-field errors are values (`{error:…}`), never exceptions that abort the batch.
- `Java.use`/`Java.choose` on an unloaded/nonexistent class → caught → `_err` with
  the navigate-first hint.
- Unknown `session_id` → `validate_session_id` → `_err`, as every tool.
- Honest empties: `instance_count == 0` is a real, guided result, not a silent
  `{}`.

## Bounding

- Instances capped at 10; declared-field count capped at 64 on the dump-all path;
  each field value clipped to `CAP=4096` by `describe()` (`index.ts:7`). Any cap
  hit sets `capped` and is noted in the summary (matching `enumerate_classes`).
  This mirrors `read_hook_events`' explicit fan-out budget (`tools.py:19`) rather
  than relying only on the host wire clamp.

## Testing

- **Unit** (fake `script.exports_sync`, as `tests/unit/test_java_introspection.py`
  / `test_java_hook_overload.py` do): canned `java_read_fields` payload → assert
  envelope shape + summary (incl. inline value and the capped note); assert the
  `_err` path on a raised exception; assert the empty-result summary guidance when
  `instance_count == 0`.
- **Handler-binding** test for `java_read_fields` (monkeypatch `java_mod`, assert a
  real envelope) so a `ToolSpec`-name / handler-name mismatch fails loudly instead
  of shipping as a silent `server.py` stub.
- **Contract** (`tests/unit/test_contract.py`): `java_read_fields` present at tier
  `high`. Bump `test_tool_count_is_18` → 19 (only A adds a `ToolSpec`; `capture_this`
  is a param on the existing `java_hook`). **Reconcile the pre-existing drift**:
  `tests/integration/test_server_list_tools.py::test_tool_count_is_15` asserts 15
  against a live 18 — update/remove it, and prefer an expected-**name-set**
  assertion over a magic number so future additions fail with a readable diff.
- **Live acceptance** (the falsification test + the untested JS branches):
  1. On the `OMTG_DATAST_011_Memory` screen, after triggering `decryptString`,
     `java_read_fields(<fqcn>, ["plainText"])` returns the plaintext in **one call**.
  2. Omit `fields` on the same class → dump-all returns `plainText` among the
     declared fields (exercises `getDeclaredFields` + resolution + field-count cap).
  3. `java_hook(<fqcn>, "decryptString", capture_this=["plainText"])` then trigger →
     `read_hook_events` shows the value under `this.plainText` at the call site.
  4. A class with a **field shadowed by a same-named method** → the value is read
     via the mangled accessor, not silently `null` (exercises the collision path).
  5. A **static** field holding a value → `java_read_fields(<fqcn>, ["<staticName>"])`
     returns it under `static_fields` with `instance_count == 0` treated as normal,
     not an error (exercises modifier dispatch + the static read path).

**Stated gap:** the TypeScript exports (`javaReadFields`, the `capture_this`
branch, the resolver) need the Frida runtime + a live VM; they are covered by the
live acceptance tests, not unit tests — same posture as `enumerate_methods`.

## Acceptance criteria

1. `java_read_fields(<OMTG_011 fqcn>, ["plainText"])` after trigger retrieves the
   plaintext in one call (root-cause falsification).
2. Omitting `fields` dumps declared fields, bounded (≤10 instances, ≤64 fields,
   per-field ≤4096B), with cap surfaced in the summary.
2a. Instance and static fields are dispatched by `Modifier.isStatic`, returned
   under `instances[].fields` and `static_fields` respectively; a static-only read
   needs no live instance.
3. `capture_this` captures `this.plainText` at the hook site, inside the
   reentrancy bracket, non-throw path only; absent `capture_this` = byte-identical
   to current `java_hook` behavior.
4. A field shadowed by a same-named method reads correctly (not `null`); a bad
   field name yields a per-field `{error}` without aborting the batch.
5. `java_read_fields` is tier `high`; `java_hook` stays `high` with its description
   disclosing the widened capture; `read_hook_events` stays `low`;
   `execute_script` stays `critical`.
6. Descriptions carry the trigger condition, the A(pull)/C(push) directional
   wording, and the `ret:null` cross-link.
7. Full unit suite green; tool-count drift reconciled; no regression to existing
   tools.
