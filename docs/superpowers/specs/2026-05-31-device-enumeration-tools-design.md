# Device-level enumeration tools: `enumerate_processes` & `enumerate_applications`

**Date:** 2026-05-31
**Status:** Approved design (revised after skeptical review)

## Problem

The worker exposes no device-level tool for listing running processes or
installed applications. In a live PARE session, the driving model was asked to
"show me the processes running on the android emulator" and had no tool for it.
It improvised by trying to `attach` to a pseudo-target (`frida-ps`) and then
`execute_script` arbitrary JS — escalating to the `critical`-risk eval path for
what should be a routine read-only lookup.

The underlying Frida capability already exists in the codebase: `attach` calls
`device.enumerate_processes()` internally to resolve a process name to a pid
(`tools.py:59`). It is simply not exposed as a standalone tool.

## Goal

Expose two device-scoped, read-only enumeration tools so the agent can list
running processes and installed packages without attaching to anything — and
without reaching for `execute_script`.

**On risk tier (corrected from the first draft):** these tools advertise
`risk_tier: "low"`, but that does *not* mean they auto-execute in PARE today.
PARE's `workers.yaml` sets the frida worker `risk_default: high` as a rollout
floor, and `resolve_declared_tier` takes `max(floor, advertised)`, so the
effective tier is currently `high` (operator approval) — the same as `attach`.
The transcript confirms this: `list_devices` (contract `low`) showed
`declared=high effective=high`. The advertised `low` is correct so the tier
resolves properly once the floor is lowered, but the concrete near-term win is
**avoiding the `critical` `execute_script` path**, not removing the approval
prompt. See the project's risk-tier-enforcement notes.

## Design

### Tools

| Tool | Frida call | Advertised risk | Inputs |
|---|---|---|---|
| `enumerate_processes` | `device.enumerate_processes()` | `low` | `device_id`, `filter`, `offset`, `limit` |
| `enumerate_applications` | `device.enumerate_applications(scope='minimal')` | `low` | `device_id`, `filter`, `offset`, `limit` |

All inputs optional. Both are **device-scoped** (`device_id`), not
session-scoped (`session_id`). They resolve a device via the existing
`devices_mod.get_device(device_id or None)` helper and never touch the session
manager or require a prior `attach`. This device-vs-session split is the crux of
the fix, so it is made explicit in the tool **descriptions** (below), not just
the parameter names.

### Tool descriptions (the discriminator must be legible in prose)

An LLM selects tools by reading descriptions, so the no-attach precondition goes
in the words, and the session-scoped enumerators are tightened to contrast:

- `enumerate_processes`: *"List processes running on a device. Device-scoped:
  needs no attach/session — pass `device_id` (or omit for the sole USB device).
  Use `filter`/`offset` to page large lists."*
- `enumerate_applications`: *"List installed apps/packages on a device.
  Device-scoped: no attach needed. `identifier` is the package name."*
- `enumerate_modules` (existing, tightened): *"List modules loaded in an
  ATTACHED process. Requires a `session_id` from `attach`."*
- `enumerate_exports` (existing, tightened): likewise note the `session_id`
  requirement.
- `execute_script` (existing, redirect added): append *"(critical/last resort).
  For listing devices, processes, applications, modules, or exports, use the
  dedicated low-risk `enumerate_*` tools instead."* — directly closes the
  recurrence path that motivated this work.

### Pagination & output (replaces the broken 200-item cap)

**Why the original cap was wrong:** `_ok`/`_err` clamp every return through
`bound_text`, which truncates raw UTF-8 bytes (`bounding.py:10-13`) with no
awareness of JSON structure. Default `max_tool_bytes` is 4096 (`config.py:19`).
A device with ~183 processes serializes to ~9–11 KB, so the byte clamp slices
the JSON mid-object and `json.loads` (used by the device tests) fails. The byte
cap bites *before* any 200-item cap, so capping by count protects nothing. The
capture-store spill that `execute_script` uses is **session-keyed** and
unreachable from device-scoped tools, so it cannot rescue this either.

**Fix — byte-aware pagination, truncating at the item level so JSON stays
valid:**

1. The device layer returns the full filtered, name-sorted list.
2. A shared `page_items(items, offset, limit, byte_budget)` helper (in
   `bounding.py`) slices from `offset`, then appends items one at a time,
   tracking serialized size, and stops before the envelope would exceed the
   budget (or before `limit`, if given). It returns `(page, next_offset,
   truncated)`.
3. Handlers always return a structured, parseable payload:

   ```json
   {
     "summary": "183 processes (showing 0–120 of 183; pass offset=120 for more)",
     "processes": [ {"pid": 1, "name": "init"}, ... ],
     "total": 183, "offset": 0, "returned": 120,
     "truncated": true, "next_offset": 120
   }
   ```

   `truncated`/`next_offset` make incompleteness explicit and pageable — no
   silent partial lists, and the agent can either page or narrow with `filter`.

### Layers (following existing seams)

1. **`core/devices.py`** — two pure functions:
   - `enumerate_processes(device, filter=None) -> list[dict]`
   - `enumerate_applications(device, filter=None) -> list[dict]`

   Each calls the Frida API, maps objects to plain dicts, and applies a
   case-insensitive substring `filter` with a **`None`-guard**: match on
   `(obj.name or "")` (and `(obj.identifier or "")` for applications), so a
   nameless kernel/zygote entry can't raise `AttributeError` and abort the whole
   listing. `enumerate_applications` passes `scope='minimal'` (verify the exact
   kwarg against the installed frida ≥17 at implementation) so the package query
   stays cheap — Python-side field trimming gives *no* fetch-cost benefit; the
   scope argument is what controls latency.

2. **`tools.py`** — two `async` handlers using the `_ok`/`_err` pattern plus
   `page_items`. Output shapes: `{pid, name}` for processes;
   `{identifier, name, pid}` for applications (`pid` is `0` when Frida reports
   the app as not running — stated as Frida's behavior, not a guarantee we test
   exhaustively).

   ```python
   async def enumerate_processes(device_id="", filter="", offset=0, limit=0):
       try:
           d = devices_mod.get_device(device_id or None)
           items = devices_mod.enumerate_processes(d, filter or None)
           page, nxt, trunc = page_items(items, offset, limit, _CAP)
           return _ok(_page_summary("processes", len(items), offset, page),
                      processes=page, total=len(items), offset=offset,
                      returned=len(page), truncated=trunc, next_offset=nxt)
       except Exception as e:
           return _err("enumerate_processes failed", e)
   ```

3. **`contract.py`** — two `ToolSpec` entries (inputs: `device_id`, `filter`,
   `offset:int`, `limit:int`). Registration in `server.py` is automatic, so no
   server changes. Implement the handlers **before** adding the specs, or
   `server.py`'s `getattr` falls back to a `_stub` that returns no
   `processes`/`applications` key (passes conformance, breaks real flows).

### Error handling & device support

`enumerate_applications` is unsupported on some device types (e.g. the `local`
system device). Behavior there is **unverified** (frida is not installed in the
design environment) — it may return `[]` rather than raise, which is
indistinguishable from "device with no apps." So the handler does not assume a
raise: it detects `device.type == "local"` (and any unsupported case) and
returns a distinct, actionable summary — *"application enumeration not supported
on device type 'local' — use enumerate_processes"* — keeping the generic
`_err(...)` only for genuine failures. Likewise, on an ambiguous/empty USB
default-device resolution, the `_err` summary should say *"multiple or zero USB
devices — call list_devices and pass device_id"* rather than surfacing a raw
frida timeout.

**Timeout caveat:** the existing `get_device(..., timeout=2)` bounds only
*device acquisition*, not the enumeration RPC. `enumerate_applications` on a
loaded Android device can take seconds. v1 documents this; running the
enumeration on a thread with a deadline is a noted follow-up, not in scope here.

### Default-device guidance

`get_device(None)` resolves to `frida.get_usb_device()`, which is unambiguous
only when exactly one USB device is attached (in the motivating transcript only
`emulator-5554` was type `usb`, so the default would resolve correctly there).
The descriptions tell the agent to omit `device_id` only with a single USB
device and otherwise call `list_devices` first.

## Testing

- **Unit** (`tests/unit/`, no device): feed the device-layer functions a fake
  device returning stub objects (including one with `name=None`); assert dict
  shape, case-insensitive substring filtering, and the `None`-guard.
- **Unit — pagination:** `page_items` returns valid, re-`json.loads`-able pages
  for a list that overflows `max_tool_bytes`; `truncated`/`next_offset` are
  correct; paging with `offset` walks the whole list without gaps or overlap.
- **Contract:** no new test needed — the dynamic conformance, list-tools, and
  risk-tier integration tests pick up the new specs automatically. Run them to
  confirm both tools advertise `low`.
- **Device** (`tests/device/test_android_flows.py`, emulator-gated): assert
  `enumerate_processes(filter=...)` *and* `enumerate_applications(...)` against
  `emulator-5554` (passing `device_id` explicitly), `json.loads` the output, and
  check a known package appears. `enumerate_applications` is the call most
  likely to behave unexpectedly, so it gets real-device coverage rather than
  only a stub.

## Out of scope

- `parameters` / icon data in output (extensible later via an opt-in
  `include_parameters` flag; the permissive output schema needs no
  `CONTRACT_VERSION` bump — note that agent_core does not validate output schemas
  at all, so this is safe by absence-of-enforcement, not by schema design).
- A sessionless / device-keyed capture store so device tools could spill to disk
  and reuse `read_capture` (possible future unification; pagination covers v1).
- Spawning/killing processes; this is read-only enumeration only.
- Lowering the worker's `risk_default` floor (a PARE-side config decision).
