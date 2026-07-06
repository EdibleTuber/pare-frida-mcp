# Hook Event Capture (decoded args + return, drain tool) — Design

**Date:** 2026-07-05
**Repo:** pare-frida-mcp
**Status:** Approved — ready for implementation plan.

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
   `flush` (clear) and `dropped_count`. **No tool drains or returns the queue** —
   the old `search_capture`/`read_capture`/`page_capture` tools were removed when
   capture became the host's job, and nothing replaced the hook-event reader. So
   captured events accumulate and eventually drop, unseen.
2. **Thin capture.** `javaHookInstall` records `args.map(String)` only. A
   `byte[]` plaintext serializes to `"[B@3f2a1c"` — junk. There is no return
   value and no decoding, so even if the events were readable there would be no
   signal in them.

The reason to put an LLM in this loop is to **cut through noise** — but that only
works if it receives decoded, structured events. The high-value work is the
decoding + return capture; the read path is a small, honest drain tool.

## Scope

**In:**
- Enriched hook capture: decoded args **and** return value (`agent/src/index.ts`).
- `read_hook_events` — a new read-only drain tool.
- Overload-resolution ergonomics for `java_hook` (helpful error listing overloads).

**Out (deferred, YAGNI):** aggregation/grouping of firings; live streaming to the
operator CLI; instance-field / `this` capture; stack traces; per-hook server-side
filters. These were explicitly considered and dropped — for the targeted hooks
that are the real workflow (one chosen method, fires per user action), firing
volume is low and the LLM does the sense-making. High volume only comes from
over-broad hooks (`String.<init>`, hot framework methods), which is an operator
footgun guarded by the cap, not a case we engineer around.

## Design

Four files. All hook capture runs on the **bundled-agent rpc path** already used
by `java_hook` / `enumerate_*` (the bundled agent imports the Java bridge).

### 1. `agent/src/index.ts` — decode + return capture

Replace the current `args.map(String)` in `javaHookInstall` with a `describe(v)`
helper, and capture the return value after calling the original. The hook remains
**observing** — it calls through and returns the original result unchanged.

```ts
function describe(v: any): any {
  if (v === null || v === undefined) return null;
  try {
    if (typeof v !== "object") return v;                 // JS primitives
    const cn = v.$className;                              // Frida-wrapped Java object
    if (cn === "java.lang.String") return v.toString();
    if (cn === "[B") {                                    // Java byte[] (descriptor "[B")
      // always hex (length-capped), utf8 when mostly-printable
      const hex = bytesToHex(v, 4096);
      const utf8 = tryUtf8(v);
      return utf8 !== null ? { utf8, hex } : { hex };
    }
    return { class: cn, value: String(v) };               // other objects: guarded
  } catch (e) { return { error: String(e) }; }
}
```

- `tryUtf8` decodes to a String and returns it only if the result is
  mostly-printable (drops binary noise). `bytesToHex` renders the length-capped
  hex. Exact printability threshold decided in implementation; hex is always
  present as the ground truth.
- The Java array representation (`$className === "[B"` for `byte[]`, index access
  for reads) is confirmed against the installed `frida-java-bridge` version during
  implementation before the decode predicate is finalized.
- Emitted event payload:
  ```
  { seq, class, method, args: [described...], ret: described, thread }
  ```
  `seq` is a per-session monotonic counter (assigned in the agent) so the drainer
  can report gaps. `thread` is `Process.getCurrentThreadId()`.
- **Recursion caveat:** `describe` itself touches `String`/array methods. Hooking
  an ultra-hot framework method (e.g. `java.lang.String.<init>`) can therefore
  flood or re-enter. We do **not** engineer around this — the drain cap + an
  explicit warning in the `java_hook` description cover it; it is an operator
  choice, the same footgun any Frida user has.

Recompile: `npm run build` in `agent/` (`frida-compile src/index.ts -o dist/agent.js -c`).

### 2. `agent/src/index.ts` + `tools.java_hook` — overload ergonomics

When `java_hook` targets a method with multiple overloads and no `overload` was
given, Frida throws a raw "has more than one overload" error. Instead, catch that
case and return a helpful `_err` listing the available overloads (reusing the
`enumerate_methods` signature strings), so the model can retry with a concrete
overload. Framework methods like `CipherOutputStream.write` need this.

### 3. `src/pare_frida_mcp/tools.py` — `read_hook_events`

```python
_EVENT_CAP = 100  # max events returned per drain; mirror in the description

async def read_hook_events(limit: int = _EVENT_CAP, session_id: str = "") -> str:
    try:
        s = _resolve_session(session_id)
        events, total, dropped = MANAGER.drain_events(s.id, limit)
        capped = total > len(events)
        note = ""
        if dropped:
            note += f"; {dropped} dropped at queue bound"
        if capped:
            note += f"; capped at {limit} - narrow your hook"
        return _ok(f"{len(events)} events{note}", events=events,
                   total=total, dropped=dropped)
    except Exception as e:
        return _err("read_hook_events failed", e)
```

- Tier **low**, read-only. Defaults to the active session (`_resolve_session`,
  the shared helper from the active-session change).
- `SessionManager.drain_events(sid, limit)` pops up to `limit` events FIFO from
  `_queue`, returns `(events, total_available, dropped_since_last_drain)`, and
  resets the per-session `dropped` counter. Draining is the natural
  clear — no separate `flush` needed for the read flow.
- The host wire-cap bounds the payload like any other tool result. No coupling to
  the shared-capture-layer fold.

### 4. `src/pare_frida_mcp/contract.py` — tool spec + description update

- New `ToolSpec("read_hook_events", "low", ...)` describing the drain-and-clear
  semantics and the `limit` cap.
- Update the `java_hook` description: it now captures **decoded args and the
  return value**, works on framework classes too (pass the `overload`), and its
  output is retrieved with `read_hook_events`. Include the hot-method flood/
  recursion warning.
- Tool count 17 → 18 (`test_contract.py::test_tool_count_is_17` becomes 18).
  `CONTRACT_VERSION` stays 1: adding a tool is additive to `list_tools()` and does
  not change the existing contract shape agent_core asserts.

## Envelope

- `read_hook_events` →
  ```
  {"summary": "<n> events[; <d> dropped...][; capped...]",
   "events": [{"seq": int, "class": str, "method": str,
               "args": [<described>...], "ret": <described>, "thread": int}, ...],
   "total": int, "dropped": int}
  ```
- `<described>` is a decoded scalar (string/number/bool/null) or an object
  (`{utf8?, hex}` for `byte[]`, `{class, value}` for other Java objects).

## Risk tiers

- `java_hook` stays **high** (observing hook; capturing the return value does not
  change target state — the original runs regardless).
- `read_hook_events` is **low** (pure read of buffered events).
- `execute_script` remains `critical`. Unchanged.

## Testing

- **Unit** (`tests/unit/`, frida stubbed):
  - `SessionManager.drain_events` — FIFO order, `limit` cap, `total`/`dropped`
    accounting, dropped-counter reset, empty-queue case.
  - `read_hook_events` tool — envelope + summary for normal / capped / dropped;
    active-session default; clear "attach first" error when no live session.
  - `contract` — `read_hook_events` present at tier `low`; tool count 18.
- **Stated gap:** the `describe()` TypeScript cannot be cleanly unit-tested (needs
  the Frida runtime + a live VM). Covered by live acceptance, not unit tests.
- **Live acceptance (KeyStore):** hook `CipherOutputStream.write([B)`; press
  ENCRYPT; `read_hook_events` returns an event whose `args[0].utf8` is the typed
  plaintext. Hook `decryptString`; press DECRYPT; a subsequent
  `String.<init>([B,int,int,String)` or the app method surfaces the recovered
  plaintext. This is the end-to-end proof the walkthrough deferred.

## Acceptance criteria

1. A hook on a method with `byte[]` args yields, via `read_hook_events`, an event
   with a `utf8`/`hex`-decoded argument (not `"[B@..."`).
2. Each event carries the method's captured `ret` (decoded), or `null` for void.
3. `read_hook_events` drains FIFO, clears what it returns, and honestly reports
   `dropped` and `capped` in its summary.
4. `java_hook` on an overloaded method with no `overload` returns an error that
   lists the available overloads.
5. `read_hook_events` is tier `low`; `java_hook` stays `high`; `execute_script`
   stays `critical`.
6. Full unit suite green; no regression to existing tools.
