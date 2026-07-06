# Hook Event Capture (decoded args + return, cursor read) — Design

**Date:** 2026-07-05
**Repo:** pare-frida-mcp
**Status:** Revised after skeptic-panel review (2026-07-06) — ready for implementation plan.

## Goal

Make `java_hook` actually useful for **capturing data**, so the model can hook a
method, trigger an action in the app, and read back the **decoded arguments and
return value** of each firing. This closes the loop the OMTG_DATAST_001_KeyStore
walkthrough left open: today you can install a hook, but nothing surfaces what it
saw.

## Why

Two stacked gaps, found while working the KeyStore challenge:

1. **No read path.** Hook `send()` events land in a bounded per-session `deque`
   (`Session._queue` in `core/sessions.py`). The only queue operations are
   `flush` (clear) and `dropped_count` — no tool drains or returns the queue, so
   captured events accumulate and eventually drop, unseen.
2. **Thin capture.** `javaHookInstall` records `args.map(String)` only. A
   `byte[]` plaintext serializes to a reference string — junk. There is no return
   value and no decoding, so even if the events were readable there would be no
   signal in them.

The reason to put an LLM in this loop is to **cut through noise** — which only
works if it receives decoded, structured events.

## Empirical facts (verified live before this revision)

Two design-critical facts were confirmed against the running target
(`emulator-5554`, frida-server 17.9.11, OMTG pid 4230) rather than assumed:

- **`byte[]` representation (frida-java-bridge, Frida 17).** A `byte[]` — whether
  constructed via `Java.array` or returned from a real Java call — is an
  **array-like object** with `Object.prototype.toString` → `"[object Object]"`,
  **`Array.isArray` → false**, **`$className` → undefined**, a numeric `length`,
  and **signed** numeric elements (e.g. `ä` → `[-61, -92]`). So the decode
  predicate is *not* `$className === "[B"` (wrong) and *not* `Array.isArray`
  (wrong): it is "object, `$className` undefined, numeric `length`, numeric
  elements", and utf8 decoding must mask `& 0xff`.
- **Host oversized-result handling is store-and-ref, not lossy truncate.**
  `agent_core/capture/layer.py` + `capture/stub.py`: a tool result over
  `max_bytes` is stored and returned as a `read_capture(ref=…)` stub. An oversized
  read is therefore **retrievable, not dropped** — so the read path is designed
  for *idempotency/retry-safety*, not against a data-loss cliff.

## Scope

**In:**
- Enriched hook capture: decoded args **and** return value, emitted as a flat,
  marked event (`agent/src/index.ts`).
- `read_hook_events` — a non-destructive, cursor-based read tool.
- Overload-resolution ergonomics for `java_hook` (explicit descriptor-list format
  + a helpful error listing overloads).

**Out (deferred, YAGNI):** aggregation/grouping of firings; live streaming to the
operator CLI; instance-field / `this` capture; stack traces; per-hook server-side
filters. For the targeted hooks that are the real workflow (one chosen method,
fires per user action), firing volume is low and the LLM does the sense-making.
High volume only comes from over-broad hooks — an operator footgun bounded by the
retention buffer, not a case we engineer around.

## Design

Four files. All hook capture runs on the **bundled-agent rpc path** already used
by `java_hook` / `enumerate_*` (the bundled agent imports the Java bridge).

### 1. `agent/src/index.ts` — decode, return capture, flat marked event

`javaHookInstall` changes so the replaced implementation:

1. decodes args via `describe`, **before** calling the original;
2. calls the original inside `try/finally`, capturing either the return value or
   the thrown exception (then re-throws — the hook stays observing);
3. emits **one flat, marked event** regardless of whether the original threw.

```ts
let SEQ = 0;                                  // per-session monotonic
const active = new Set<number>();             // thread-ids currently inside a hook body

function emit(cls, method, overload, argsD, retD, threw) {
  send({ hook: true, seq: ++SEQ, class: cls, method, overload,
         args: argsD, ret: retD, threw, thread: Process.getCurrentThreadId() });
}
```

**Re-entrancy guard.** `describe`/`emit` can touch string/array operations; if the
hooked method is itself on that path (e.g. `String.<init>`), the body would
re-enter unboundedly and crash the target. The body checks `active` for the
current thread-id: on re-entry it emits a minimal `{ reentrant: true }` event and
does **not** decode. This is what actually covers recursion — the retention buffer
covers *flood*, not recursion (correcting the prior draft's claim).

**`describe(v)` — pure-JS decode, capped at the top:**

```ts
const CAP = 4096;                             // bytes/chars, applied to EVERY path
function describe(v: any): any {
  if (v === null || v === undefined) return null;
  if (typeof v !== "object") return v;                       // JS primitives
  try {
    const cn = v.$className;
    if (cn === "java.lang.String") return clip(v.toString(), CAP);
    if (cn === undefined && typeof v.length === "number" &&
        (v.length === 0 || typeof v[0] === "number")) {      // byte[]/primitive array
      const n = Math.min(v.length, CAP);
      const hex = hexJS(v, n);                                // pure JS, (b & 0xff)
      const utf8 = utf8JS(v, n);                              // pure JS multibyte walk, & 0xff
      const out: any = { hex, len: v.length };
      if (utf8 !== null) out.utf8 = utf8;                     // only on a valid decode
      return out;
    }
    return { class: cn || "?", value: clip(String(v), CAP) };
  } catch (e) { return { error: String(e) }; }
}
```

- `hexJS` and `utf8JS` are implemented **in JS** (index access + `& 0xff`; a manual
  UTF-8 walker that sets `utf8` only on a valid decode, never on U+FFFD mojibake) —
  no Java `String`/array allocation, so `describe` never re-enters a hooked Java
  method. `clip` bounds every path so no unbounded `String(v)`/walk runs inline in
  a hot hook.
- Event lives at the Frida message's single `payload` (the agent sends the flat
  object directly — no redundant `{type:'send',source}` wrapper), tagged
  `hook: true` so the reader can filter it from frida `error`/`log` messages.

Recompile: `npm run build` in `agent/` (`frida-compile src/index.ts -o dist/agent.js -c`).

### 2. Overload resolution — `agent/src/index.ts` + `tools.java_hook`

Frida's `.overload()` takes **one type descriptor per argument** as varargs, so a
single joined string cannot select a multi-argument overload (e.g.
`CipherOutputStream.write([B,int,int)`).

- **Wire format:** `overload` becomes an **ordered list of frida type descriptors**
  (e.g. `["[B", "int", "int"]`), spread into `klass[method].overload(...types)`.
  The single-descriptor case (`["[B"]`) still works.
- **Helpful error:** when the method has multiple overloads and none was given,
  return an `_err` whose payload carries a structured
  `overloads: [["[B"], ["[B","int","int"], ["int"]]` — exactly the descriptor
  lists the model can pass back verbatim (frida descriptor spelling, e.g. `[B`,
  not `enumerate_methods`' `toString()` output).

The resolved descriptor list is recorded on each event (`overload`) so interleaved
firings from different overloads of the same `class.method` are attributable.

### 3. `read_hook_events` — non-destructive cursor read

Replaces the per-session drain deque with a **bounded retained buffer** of flat
events keyed by `seq`. Reads are **non-destructive**: the client passes the last
`seq` it consumed; eviction happens only by ring overflow, never by reading.

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

`SessionManager.read_events(sid, since_seq, limit, max_bytes)` returns events with
`seq > since_seq` in order, stopping at whichever bound (`limit` **or**
`max_bytes`) is hit first, and reports:

- `next_seq` — `seq` of the last event returned (or `since_seq` if none); the
  cursor to pass to the next call.
- `buffered_remaining` / `has_more` — events still retained past `next_seq`
  (replaces the ambiguous `total`; `has_more` distinguishes *pagination* from
  *loss*).
- `lost` — count of events evicted below the requested `since_seq` (the cursor
  fell behind the ring). This is the **only** true-loss signal, derived from
  `seq` on the read thread — race-free, replacing the cross-thread `dropped`
  counter entirely.

`max_bytes` (`_EVENT_WIRE_BUDGET`) is set **below** the host `max_bytes` so a
normal read never trips the capture-store stub; a fat single event still surfaces
(then `read_capture` remains the host's fallback). `_on_message` filters to
`payload.get("hook")` and appends the flat event; frida `error`/`log` messages are
kept in a separate small buffer and never pollute the event stream or its counts.

The retention buffer is bounded by an **item count chosen for enriched-event
size** — the existing `queue_bound=10000` assumed the old thin `args.map(String)`
messages; enriched events carry up to `CAP` bytes of hex + utf8, so worst-case
resident memory is `bound × per-event-max`. The bound is set deliberately (and
documented) against that product, not inherited from the thin-message era.

**Readiness.** `java_hook` returns the current max `seq` as `since_seq` at install
time. The model reads with that cursor; an empty result means *the operator has
not triggered the action yet* — retry after the action, do not tear the hook down.
This is stated in both tool descriptions (the trigger is a physical action, not a
tool call, so hook→read can otherwise race to an empty first read).

### 4. `contract.py` — tool spec + descriptions + tiers

- New `ToolSpec("read_hook_events", "low", …)`: cursor semantics (`since_seq`,
  `limit`), `has_more` vs `lost`, and the readiness note. **Tier `low` with an
  explicit rationale**: the sensitive act — choosing what to capture — is already
  gated at `java_hook` = `high`; retrieving the already-captured buffer need not
  re-gate. (Noted because `read_memory` is `high`; the distinction is
  capture-gated-upstream, not "pure read".)
- `java_hook` description updated: captures **decoded args and return value**,
  works on framework classes, takes an **ordered descriptor-list** `overload`, and
  its output is read via `read_hook_events`; includes the hot-method
  flood/recursion note.
- `input_schema` for both: `limit` documented with its clamp; `since_seq` an
  integer ≥ 0.
- Tool count 17 → 18 (`test_contract.py::test_tool_count_is_17` → 18).
  `CONTRACT_VERSION` stays 1 (additive to `list_tools()`).

## Envelope

```
read_hook_events -> {
  "summary": "<n> events[; <k> evicted...][; <m> more - call again with since_seq=<s>]",
  "events": [{"seq": int, "class": str, "method": str, "overload": [str,...],
              "args": [<described>...], "ret": <described>, "threw": bool,
              "thread": int}, ...],
  "next_seq": int, "buffered_remaining": int, "has_more": bool, "lost": int
}
```

`<described>` is a decoded scalar (string/number/bool/null) or an object:
`{hex, len, utf8?}` for a `byte[]`/primitive array, `{class, value}` for other
Java objects, `{reentrant: true}` when the re-entrancy guard fired,
`{error: str}` on a decode failure.

## Risk tiers

- `java_hook` stays **high** (observing hook; capturing the return does not change
  target state — the original runs regardless).
- `read_hook_events` is **low** (non-destructive read; capture already gated at
  `java_hook`).
- `execute_script` remains `critical`. Unchanged.

## Testing

- **Unit** (`tests/unit/`, frida stubbed):
  - `SessionManager.read_events` — `seq > since_seq` selection, `limit` and
    `max_bytes` bounds (whichever first), `next_seq`/`buffered_remaining`/
    `has_more`, `lost` when the cursor falls below the retained window, and the
    hook-marker filter (frida `error`/`log` messages excluded from events/counts).
  - `read_hook_events` tool — envelope + summary for normal / has_more / lost;
    `limit` clamp and `since_seq < 0`; active-session default; clear "attach
    first" error when no live session.
  - `contract` — `read_hook_events` present at tier `low`; tool count 18.
- **Stated gap:** the `describe()` / decode TypeScript cannot be cleanly
  unit-tested (needs the Frida runtime + a live VM). Covered by live acceptance.
- **Live acceptance (KeyStore):**
  1. Hook `CipherOutputStream.write` with `overload=["[B"]`; press ENCRYPT;
     `read_hook_events(since_seq=<install baseline>)` returns an event whose
     `args[0].utf8` is the typed plaintext (exercises byte[] decode **and**
     overload resolution). This is the end-to-end proof the walkthrough deferred.
  2. Re-entrancy guard holds: hook `java.lang.String.<init>` `["[B","int","int","java.lang.String"]`
     and confirm the target does **not** crash and events carry `reentrant: true`
     rather than recursing.

## Acceptance criteria

1. A hook on a `byte[]`-arg method yields, via `read_hook_events`, an event with a
   `utf8`/`hex`-decoded argument (verified predicate: array-like, `$className`
   undefined, numeric elements; utf8 masks `& 0xff`).
2. Each event carries the method's captured `ret` (decoded) or `threw: true` on
   the exception path — an event is emitted even when the original throws.
3. `read_hook_events` is idempotent: the same `since_seq` returns the same events;
   `has_more` signals pagination (call again) and `lost` signals eviction — the
   two are never conflated.
4. `java_hook` on an overloaded method with no `overload` returns an error listing
   the available descriptor lists; a multi-arg overload is selectable via the
   descriptor-list format.
5. Hooking `String.<init>` does not crash the target (re-entrancy guard); no
   `describe` path runs an unbounded operation inline.
6. `read_hook_events` is tier `low`; `java_hook` stays `high`; `execute_script`
   stays `critical`.
7. Full unit suite green; no regression to existing tools.
