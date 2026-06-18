# Design: `enumerate_modules` / `enumerate_exports` → `@snapshots` consumers

**Date:** 2026-06-17
**Repo:** `pare-frida-mcp` (Android v1 Frida worker)
**Status:** Approved design — ready for implementation plan

## Problem

`enumerate_modules` and `enumerate_exports` currently return their results
**inline but capped**. The tool body enumerates the full list, then `fit_items`
trims it to `_CAP` bytes and appends a truncation note (`enumerate_modules`)
or count note (`enumerate_exports`), with `filter=` offered as a narrowing knob.

Two problems follow:

1. **The operator never reliably sees the whole list.** A process with hundreds
   of modules (Lunchbox shows ~425) is silently truncated; the operator has to
   guess a `filter=` to see more.
2. **It is inconsistent with the rest of the enumeration surface.**
   `enumerate_processes` and `enumerate_applications` are already handle-only
   `@snapshots` consumers (persist-then-search). Modules/exports are the odd
   pair still dumping capped JSON inline.

## Goal

Convert both tools to **handle-only `@snapshots` consumers**, matching
`enumerate_processes`/`enumerate_applications`. The full, untruncated list is
persisted to the snapshot store; the tool returns only a handle + count. The
data then serves two consumers off one store:

- the **operator** views the **complete** list via `/snapshot` (`page_capture`,
  unbounded — this is the path that shows all rows, never sampled);
- the **LLM** pulls **narrow** context on demand via a `text=` search,
  `search_capture(session_id='@snapshots', text='<symbol-or-lib>')`, which
  returns just the matching rows.

> Important: a whole-snapshot dump via `search_capture(field='source',
> contains=<key>)` is **bounded and spread-sampled** (`capture/search.py`), so
> for a large snapshot (~425 modules; far more per-module exports) it comes back
> *truncated*, not complete. The complete-list path is `/snapshot`, not a
> source-key dump. Guidance and tests must reflect this (see Retrieval
> semantics).

## Non-goals

- The operator-facing `/modules` / `/exports` slash commands. Those live in the
  PARE repo and build on this conversion; designed separately.
- Per-session snapshot namespacing / changing the LRU bound (see Known bounds).
- Any change to `read_memory`, `java_hook`, or other session tools.

## Design

### Shape (mirrors `enumerate_processes`)

Each tool body:

1. `sid = validate_session_id(session_id)`; `s = MANAGER.get(sid)`.
2. Enumerate the **full** list via `memory_mod.enumerate_modules(s.script)` /
   `enumerate_exports(s.script, module)`. No `fit_items`, no cap.
3. `n = SNAPSHOTS.replace(key, items, summary_field="name")`.
4. Return `_ok(<guidance>, store=SNAPSHOT_HANDLE, source=key, total=n)`.

Guidance string leads with the complete-list path (`/snapshot`) and a narrow
`text=` search, **not** a source-key dump:

> `"{n} modules captured to @snapshots. Run /snapshot to view the full list, or
> search_capture(session_id='@snapshots', text='<lib-or-symbol>') to find
> specific entries."`

(`enumerate_exports` uses the same shape with "exports for {module}".)

The item shapes are confirmed against the live agent (`agent/src/index.ts`):
modules are `{name, base, size}`, exports are `{name, address}`. Both carry a
`name`, so `summary_field="name"` is correct for each — same as `processes`
(`name`) and `applications` (`identifier`).

### Snapshot keys (session-scoped)

This is the one structural difference from the device-scoped consumers: modules
and exports are meaningful only relative to an attached process, so the key is
scoped on the session, via the existing `snapshot_key(tool, **kwargs)` helper
(which percent-encodes and sorts non-empty args):

- modules → `snapshot_key("enumerate_modules", session=sid)`
  → `enumerate_modules:session=<sid>`
- exports → `snapshot_key("enumerate_exports", session=sid, module=module)`

`session=sid` keeps two attached processes from clobbering each other's module
maps; `module=` keeps each module's exports in its own snapshot. Re-running a
query upserts its own key via `SnapshotStore.replace` (delete-by-source then
re-insert), so a re-enumerate **within the same live session** refreshes in
place (see Session lifecycle for cross-session behavior).

**The key is percent-encoded, not the human form.** `snapshot_key` runs each
segment through `quote()`, which encodes path and special characters: a module
named `libc++.so` keys as `enumerate_exports:module=libc%2B%2B.so:session=<sid>`
and `/system/lib64/libc.so` as `…module=%2Fsystem%2Flib64%2Flibc.so…`. So the
spec's `module=<module>` is shorthand for the *encoded* value. Consumers (LLM or
operator) must **copy the echoed `source` key verbatim** from the tool result —
never hand-assemble it from the human module name.

### Retrieval semantics (LIKE, not FTS)

`search_capture(field='source', contains=<key>)` resolves to a SQL
`LIKE '%<key>%'` on the `source` column (`capture/search.py`) — a plain
substring match, **no FTS tokenization**, so dotted names like
`libandroid_runtime.so` are *not* a hazard here. The real hazard is `LIKE`
metacharacters: `_` matches any single char and `%` matches any run, and neither
`quote()` nor the current query escapes them. Android lib names are full of `_`,
so `contains=<modules-key-or-exports-key>` can over-match a sibling snapshot
(verified: a key for `libandroid_runtime.so` matches `libandroidXruntime.so`).

Fix as part of this work: have the `source`/`contains=` path use
`LIKE ? ESCAPE '\'` and escape `_`/`%`/`\` in the `contains` value (in
`capture/search.py`). This is a small, general correctness fix that also hardens
the existing `enumerate_processes`/`applications` consumers. Exact-snapshot
selection should otherwise prefer the verbatim echoed key (e.g. `/snapshot`
against that source), not a fuzzy substring.

### Session lifecycle

The snapshot key embeds `session=<sid>`, and `sid` is a fresh UUID per attach
(`new_session_id()`), so the lifecycle must be stated explicitly:

- **Refresh-in-place is scoped to one live session.** `attach → enumerate →
  detach → re-attach → enumerate` writes a *new* key (new sid) — a fresh
  snapshot, by design, not a refresh of the old one.
- **`detach` purges that session's snapshots.** Today `detach`
  (`core/sessions.py`) closes the per-session capture store but never touches
  `SNAPSHOTS`, leaving a dead session's module/export maps queryable until LRU
  eviction — exactly the "stale view is wrong" the output policy forbids. So
  `detach` must purge keys for that sid. `SnapshotStore` currently only deletes
  by *exact* source; add a small prefix/predicate-delete helper (delete all
  sources containing `session=<sid>`) and call it from `detach`.

### Contract changes

- **`enumerate_modules` drops its `filter=` parameter** — removed from **both**
  the Python handler signature (FastMCP derives the wire input schema from it)
  **and** the `ToolSpec.input_schema` in `contract.py` (the conformance / PARE
  view). Removing it from only one desyncs advertised-vs-actual. Post-persist
  narrowing is now a `text=` search, so the param only re-introduces the
  truncation mindset and a second code path. The new body calls
  `memory_mod.enumerate_modules(s.script)` with **no** filter arg (relying on
  `memory.py`'s `filter=None` default, which sends `""` → full list); the JS
  agent's `modules(filter)` argument is left untouched (receives `""`,
  harmlessly), so **no `memory.py` or agent change and no re-bundle**.
  `enumerate_modules` stays `risk_tier="low"`, and PARE keys `risk_overrides` on
  name+tier only, so gating is unaffected.
- **`enumerate_exports` keeps `module=`** — it is a required selector, not a
  cap, and is part of the snapshot key.
- Description text in both `ToolSpec`s updated to state the handle-only
  behavior and reference `@snapshots` (matching the processes/applications
  entries).

### Known bounds (documented, not engineered around)

The snapshot store is an LRU over distinct keys (`max_keys=32`). Two concrete,
operator-facing consequences of per-module exports keys — acceptable for v1
(re-enumerate is cheap), but documented rather than vaguely waved at:

- **A bare `/snapshot` resolves to the MRU source.** After enumerating any
  module's exports, that exports snapshot becomes most-recently-used, so a bare
  `/snapshot` no longer shows the modules list. Guidance: use
  `/snapshot <key-substring>` (e.g. `/snapshot modules`) to target the one you
  want. As a cheap nicety, the exports body MAY touch the modules key to keep it
  MRU — optional, not required.
- **An exports-walk can evict the modules list.** Enumerating exports across
  >31 native libs in one session fills the 32-slot LRU and silently evicts the
  modules-list snapshot the operator is working from. Recoverable by re-running
  `enumerate_modules`. No per-session namespacing is added now (YAGNI); the
  `max_keys` bound is already tunable if a real workflow needs more.

Note these are an LRU *cache*'s normal behavior; the operator-facing docs should
say so in one line (snapshots are a bounded cache, re-enumerate to refresh).

### Code style & comments

New/rewritten code matches the existing comment density in `tools.py` — terse,
explaining *intent* over mechanics. Specifically, comment the two non-obvious
points so a future reader needn't reverse-engineer them:

- **why the snapshot key is session-scoped** (and includes `module=` for
  exports) — i.e. modules/exports are meaningful only per attached process, so
  the key must not collide across sessions;
- **that the full list is persisted uncapped on purpose** — the handle-only
  return is deliberate context economy (persist-then-search), not an oversight;
  no `fit_items`.

The `SnapshotStore` methods already carry explanatory docstrings; the tool
bodies should read like `enumerate_processes` with these two intent comments
added.

## Documentation

Documentation updates are part of this work, not a follow-up. The conversion
changes user-visible behavior and closes a tracked gap, so the docs must move
with the code:

- **`docs/superpowers/tool-output-policy.md` (this repo) — primary.** This doc
  tracks the conversion as *"the standout gap"* and lists
  `enumerate_modules` / `enumerate_exports` as `inline (large lists)` →
  "convert to store consumers (next effort)". Flip their row to
  `@snapshots ✓ / done` (matching `enumerate_processes`), and update the prose
  that calls them the standout gap so the doc no longer advertises an open gap.
- **`README.md` (this repo) — verify-only (expected no-op).** It describes the
  "memory-inspection surface (enumerate / read / write)" and does not imply
  inline module output, so no edit is expected. Listed only to confirm, not to
  force-edit.
- **`~/Projects/PARE/docs/frida-quickstart.md` (PARE repo) — cross-repo, full
  reconciliation.** This is `pare-frida-mcp`'s operator-facing doc and lives in
  PARE because the worker is a tightly-integrated PARE module. Its tool table is
  already broadly stale, so a two-row flip would leave it self-contradicting.
  Reconcile the **whole table against `contract.py`**: fix the "13 tools" count;
  add the missing tools (`list_sessions`, `detach`, `enumerate_processes`,
  `enumerate_applications`, `page_capture`); correct wire tiers that disagree
  with `contract.py` (e.g. `java_hook`, `read_memory` are `high`); and update
  the `enumerate_modules` / `enumerate_exports` rows + session-lifecycle notes to
  the handle-only `@snapshots` behavior (full list via `/snapshot`, narrow via
  `text=` search). Call this out in the plan as a **distinct PARE-repo step**
  (its own commit/PR) so it isn't lost when the worker change merges alone.

## Error handling

Unchanged in spirit. Both tools keep their `try/except` wrapper returning
`_err("enumerate_modules failed", e)` / `_err("enumerate_exports failed", e)`.
`validate_session_id` and `MANAGER.get` continue to surface a clear error when
called without a live session (these tools require an attached session).

> Out-of-scope observation surfaced during design: PARE's CLI renders only the
> `_err` `summary`, hiding the `detail` field (`{type}: {exc}`). Not fixed here;
> noted for a PARE-side follow-up — surfacing `detail` would materially speed
> up frida-layer diagnosis.

## Testing

### Unit (`tests/unit/test_ok_floor_data_loss.py` and a snapshot test)

The return shape changes from `modules=[…]` / `exports=[…]` to
`store=@snapshots, source=<key>, total=n`. The existing tests break in specific
ways that must be fixed, not just "updated":

- **Monkeypatch arity.** The current `enumerate_modules` monkeypatch is
  `lambda script, filt: …` (two args); the new body calls
  `memory_mod.enumerate_modules(s.script)` with one, raising a `TypeError` the
  `except` wrapper swallows into a misleading `_err`. Change it to
  `lambda script: …` (or `lambda script, *a:`). The `enumerate_exports`
  monkeypatch keeps `module=` and is unaffected.
- **Assert against the right store.** The new bodies persist via the
  module-global `SNAPSHOTS` (like `enumerate_processes`), *not*
  `_DummySession.store`. Assertions must query `T.SNAPSHOTS.store`; the autouse
  `_fresh_snapshots` fixture already isolates it per test.

New unit cases:

- **Shape:** `enumerate_modules` / `enumerate_exports` return the echoed
  `source` key + `total=n`, and `T.SNAPSHOTS.store` holds `n` rows under that key.
- **`filter` removal (schema-level, not runtime):** assert `'filter' not in`
  the `enumerate_modules` `ToolSpec.input_schema['properties']`, and that
  `enumerate_exports` still has `'module'`. (A runtime
  `enumerate_modules(sid, filter='x')` would raise `TypeError` at the Python
  boundary — too brittle; assert the schema.)
- **No-live-session error path** (the behavior the spec claims to preserve):
  `enumerate_modules('<bogus-sid>')` and
  `enumerate_exports('<bogus-sid>', module='x')` return an `_err` envelope
  (`error: true`, no `source` key).
- **Edge cases:** empty list → `total=0` with a clean envelope; re-enumerate
  with a changed item set reflects only the new rows under the *same*
  `enumerate_modules:session=<sid>` key; two different `module=` values under one
  session produce *distinct, coexisting* sources (mirror `test_distinct_keys_coexist`).
- **`LIKE` metacharacter safety:** a module name containing `_` and `+` keys
  round-trips, and `contains=<that key>` does **not** match a near-sibling key
  (pins the `LIKE ? ESCAPE` fix).

Full LRU-eviction-under-load stays out of scope — the generic LRU is already
covered by the store tests.

### Device (`tests/device/test_android_flows.py`)

- The existing `test_attach_enumerate_read` flow is **not** a pure enumerate: it
  reads `mods['modules']` inline, picks `libc`, and feeds `libc['base']` into
  `read_memory`. With the handle-only shape that base must be recovered from a
  `search_capture` match — and the `payload` column comes back as a JSON
  *string* (`search._lean`), so `json.loads` it before indexing `['base']`.
  (Alternatively split into a pure-enumerate test + a separate `read_memory`
  test.)
- Keep exercising the **large** list (the whole point): after attach assert the
  persisted `total` is large (e.g. `> 50` on a real process) **and** that a
  narrow `search_capture(text='libc')` returns the match — proving the uncapped
  persist, not just that one row comes back. Do **not** narrow the test to a
  `field='source'` dump (that path is sampled/capped).

## Files touched

- `src/pare_frida_mcp/tools.py` — rewrite `enumerate_modules` / `enumerate_exports` bodies (handle-only; call `enumerate_modules(s.script)` with no filter arg).
- `src/pare_frida_mcp/contract.py` — drop `filter` from the `enumerate_modules` Python signature **and** `ToolSpec.input_schema`; update both descriptions to the handle-only behavior.
- `src/pare_frida_mcp/core/snapshots.py` — add a prefix/predicate-delete helper (delete sources containing `session=<sid>`) for the detach purge.
- `src/pare_frida_mcp/core/sessions.py` — `detach` calls the purge helper so a torn-down session's snapshots don't linger.
- `src/pare_frida_mcp/capture/search.py` — `field='source'`/`contains=` uses `LIKE ? ESCAPE` and escapes `_`/`%`/`\` (general fix; also hardens existing consumers).
- `tests/unit/test_ok_floor_data_loss.py` (+ snapshot unit test), `tests/device/test_android_flows.py` — fix the monkeypatch arity / store target / `read_memory` JSON recovery, and add the new cases above.
- `core/memory.py`, `agent/src/index.ts` — **unchanged** (agent `filter` arg left as a no-op; no re-bundle).
- `docs/superpowers/tool-output-policy.md` — flip the modules/exports status to done; drop "standout gap" prose.
- `README.md` (this repo) — verify-only, expected no-op.
- `~/Projects/PARE/docs/frida-quickstart.md` (PARE repo) — **full tool-table reconciliation against `contract.py`** + the new `@snapshots` behavior; distinct PARE-repo step/commit.
