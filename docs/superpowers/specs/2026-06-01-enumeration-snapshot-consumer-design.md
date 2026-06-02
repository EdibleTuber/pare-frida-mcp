# Device enumeration tools as snapshot-store consumers

**Date:** 2026-06-01
**Status:** Approved design
**Supersedes:** `2026-05-31-device-enumeration-tools-design.md` (paused — predated the snapshot store)

## Problem

The worker exposes no device-level tool for listing running processes or
installed applications. In a live PARE session the driving model was asked to
"show me the processes running on the android emulator," had no tool for it, and
improvised by `attach`-ing to a pseudo-target and `execute_script`-ing arbitrary
JS — escalating to the `critical`-risk eval path for a routine read-only lookup.

The Frida capability already exists internally (`attach` calls
`device.enumerate_processes()` to resolve a pid). It is simply not exposed as a
standalone tool.

## Why this supersedes the paused plan

The earlier design (2026-05-31) was written *before* the snapshot store existed.
Its central decision was to **not** use a capture store — "session-keyed and
unreachable from device-scoped tools" — and instead return the full list via
byte-aware inline pagination (`page_items`).

That premise is now obsolete. The sessionless snapshot store landed precisely so
device-scoped tools could persist-then-search:

- `SnapshotStore` with `replace()` / `snapshot_key()` / LRU bound / `@snapshots`
  handle (`core/snapshots.py`).
- `search_capture` / `read_capture` already route to `@snapshots` via
  `_resolve_store()` (`tools.py`).
- The shared in-memory `CaptureStore` indexes **both `summary` and `payload`** in
  FTS5 (`store.py:25-26`, `122-125`).

So enumeration is rewritten as a **consumer** of that store: enumerate → persist
→ return a tiny handle, never the list inline.

## Design

### Strict handle-only (persist-then-search)

A local model drives and consumes PARE, so the contract is deliberately minimal:
one obvious retrieval path, no inline lists, no cursor arithmetic. Each handler
returns only a summary + the `@snapshots` handle + the `source` key + `total`.
There is **no inline preview**, even for small results — the model always reads
via `search_capture`/`read_capture`. ("Enumerate once, search many.")

### Tools

| Tool | Frida call | Advertised risk | Inputs |
|---|---|---|---|
| `enumerate_processes` | `device.enumerate_processes()` | `low` | `device_id` |
| `enumerate_applications` | `device.enumerate_applications(scope='minimal')` | `low` | `device_id` |

Both are **device-scoped** (no `session_id`, no prior `attach`), resolving via
`devices_mod.get_device(device_id or None)`. `filter`/`offset`/`limit` from the
paused plan are **removed** — filtering now lives in `search_capture`.

**On risk tier:** the tools advertise `low`, but PARE floors the frida worker at
`risk_default: high`, and `resolve_declared_tier` takes `max(floor, advertised)`,
so the effective tier is currently `high` (operator approval). The advertised
`low` is correct so the tier resolves properly once the floor is lowered; the
concrete near-term win is **avoiding the `critical` `execute_script` path**, not
removing the approval prompt.

### Handler shape

```python
async def enumerate_processes(device_id: str = "") -> str:
    try:
        d = devices_mod.get_device(device_id or None)
        items = devices_mod.enumerate_processes(d)          # full list, no filter
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

### Key normalization (`device.id`, not the raw argument)

The key uses the **resolved** `device.id`, which lives in the same namespace as
the `device_id` *input* (`enumerate_devices` maps `{"id": d.id, ...}`;
`get_device` resolves via `frida.get_device(device_id)` against that same `id`).
So omitting `device_id` (default USB device, `.id == "emulator-5554"`) and
passing it explicitly collapse to **one** key —
`enumerate_processes:device=emulator-5554` — instead of two near-duplicate
snapshots. `getattr(d, "id", "") or ""` degrades safely to a keyless key rather
than throwing if `id` is unpopulated.

### Summary field — identifier is primary for apps

For an RE agent the package identifier (`com.example.bank`) is the relevant key,
not the display name. So `enumerate_applications` writes with
`summary_field="identifier"`, making the at-a-glance `summary` column the package
name. `enumerate_processes` uses `summary_field="name"` (the process name).

The identifier is searchable regardless: `replace()` stores the whole item dict
as `payload`, and FTS indexes `payload`, so `text=` reaches it. The summary field
only controls the glance-value, not reachability.

### Retrieval contract for the local model

The handler's summary string *names the next call*. Two paths:

- **Deterministic (primary):** `search_capture("@snapshots", field="source",
  contains="<key>")` — plain SQL `LIKE` (`search.py:25-34`), no FTS tokenizer, so
  dotted package names are safe. This is the recipe embedded in the summary.
- **Fuzzy (secondary):** `search_capture("@snapshots", text="bank")` — FTS across
  `summary`+`payload`, for "find anything matching" across snapshots. Note the
  FTS unicode61 tokenizer splits on `.`, so a dotted identifier tokenizes to
  `com`/`example`/`bank`; bare-term matching works, exact dotted-string matching
  is best done via the deterministic `source` path.

### Device-layer functions (`core/devices.py`)

Two pure functions — map Frida objects to plain dicts and sort
case-insensitively, with a `None`-name guard so a nameless kernel/zygote entry
can't raise mid-listing. No `filter` parameter (removed with inline pagination).

```python
def enumerate_processes(device) -> list[dict]:
    procs = [{"pid": p.pid, "name": p.name} for p in device.enumerate_processes()]
    procs.sort(key=lambda p: (p["name"] or "").lower())
    return procs


def enumerate_applications(device) -> list[dict]:
    try:
        apps = device.enumerate_applications(scope="minimal")
    except TypeError:
        apps = device.enumerate_applications()  # builds whose signature differs
    out = [{"identifier": a.identifier, "name": a.name, "pid": a.pid} for a in apps]
    out.sort(key=lambda a: (a["identifier"] or "").lower())
    return out
```

`scope='minimal'` controls Frida's fetch cost on Android (verify the exact kwarg
against the installed frida ≥17 at implementation); the `TypeError` fallback
covers builds whose signature differs. Output shapes: `{pid, name}` for
processes; `{identifier, name, pid}` for applications (`pid` is `0` when Frida
reports the app as not running).

### Tool descriptions (the discriminator must be legible in prose)

An LLM selects tools by reading descriptions, so the no-attach precondition and
the persist-then-search retrieval go in the words:

- `enumerate_processes`: *"List processes running on a device into the
  @snapshots store. Device-scoped: needs no attach/session — pass device_id (or
  omit for the sole USB device). Returns a source key; read results with
  search_capture(session_id='@snapshots', field='source', contains=<key>)."*
- `enumerate_applications`: *"List installed apps/packages on a device into the
  @snapshots store. Device-scoped: no attach needed. 'identifier' is the package
  name. Returns a source key; read with search_capture as above."*
- `enumerate_modules` (existing, tighten): *"List modules loaded in an ATTACHED
  process (requires session_id from attach)."*
- `enumerate_exports` (existing, tighten): *"List exports of a module in an
  ATTACHED process (requires session_id from attach)."*
- `execute_script` (existing, redirect): append *"(critical/last resort). For
  listing devices, processes, applications, modules, or exports, use the
  dedicated low-risk enumerate_* tools instead."* — closes the recurrence path
  that motivated this work.

### Error handling & device support

- `enumerate_applications` on the `local` system device is unsupported; the
  handler short-circuits on `device.type == "local"` with a distinct, actionable
  `_ok` summary (not an `_err`), writing no snapshot.
- On ambiguous/empty USB default-device resolution, the `_err` summary should say
  *"multiple or zero USB devices — call list_devices and pass device_id"* rather
  than surfacing a raw frida timeout.
- **Timeout caveat:** `get_device(..., timeout=2)` bounds only device
  *acquisition*, not the enumeration RPC. `enumerate_applications` on a loaded
  Android device can take seconds. v1 documents this; running the enumeration on
  a thread with a deadline is a noted follow-up, not in scope.

## What changes

- `core/devices.py` — **add** `enumerate_processes(device)`,
  `enumerate_applications(device)` (pure map + sort, `None`-guard).
- `tools.py` — **add** `enumerate_processes`, `enumerate_applications` handlers;
  import `snapshot_key`, `SNAPSHOT_HANDLE`. (`SNAPSHOTS`, `_resolve_store`
  already exist.)
- `contract.py` — **add** two `ToolSpec`s (`device_id` only, `risk_tier "low"`);
  **tighten** `execute_script`, `enumerate_modules`, `enumerate_exports`
  descriptions. Registration in `server.py` is automatic — implement handlers
  *before* adding specs, or `server.py`'s `getattr` falls back to a `_stub`.
- `bounding.py` — **remove** `page_items` (dead code; only its own tests
  referenced it, and the inline-pagination approach it served is abandoned).
- `tests/unit/test_bounding.py` — **remove** the `page_items` tests.

## Testing

- **Unit — device layer** (`tests/unit/test_device_enum.py`, create): feed the
  functions a fake device returning stub objects (including one with
  `name=None`); assert dict shape and case-insensitive sort; assert the
  `None`-guard does not crash; assert `enumerate_applications` requests
  `scope="minimal"`.
- **Unit — handlers** (`tests/unit/test_tools_enum.py`, create) — the real
  persist-then-search win, end to end:
  - monkeypatch `devices_mod.get_device`; call `enumerate_processes`; assert the
    return carries `store="@snapshots"`, a `source` key, and `total`; assert the
    rows actually landed by calling `search_capture("@snapshots", field="source",
    contains=key)` and getting them back.
  - **replace semantics:** call twice with a changed list under the same resolved
    device; assert only the fresh rows remain for that key.
  - **key normalization:** omitting `device_id` and passing the resolved id
    produce the same `source` key (one snapshot).
  - **local short-circuit:** `enumerate_applications` on a `type="local"` fake
    returns an `_ok` "not supported" summary, `total=0`, and writes nothing.
  - **identifier glance-value:** an app row's `summary` equals its identifier.
- **Integration:** existing dynamic conformance / `list_tools` / risk-tier tests
  pick up the new specs automatically; extend the `list_tools` subset assertion
  to require `enumerate_processes`/`enumerate_applications`, and confirm both
  advertise `low`.
- **Device** (`tests/device/test_android_flows.py`, emulator-gated): call
  `enumerate_processes(device_id="emulator-5554")` and
  `enumerate_applications(device_id="emulator-5554")`, then
  `search_capture("@snapshots", field="source", contains=<key>)` and assert a
  known package (e.g. contains `settings`) appears in the retrieved rows.

## Out of scope

- Lowering the worker's `risk_default` floor (a PARE-side config decision).
- Spawning/killing processes; this is read-only enumeration only.
- On-disk durability for snapshots (regenerate cheaply; in-memory by design).
- Trimming the null frida-stream columns (`hook`/`url`/`method`/`cls`/`ret`/
  `blob_ref`) from `search_capture` result rows — a shared session-path cleanup,
  separate from this work.
- `parameters` / icon data in application output (extensible later via an opt-in
  flag).
