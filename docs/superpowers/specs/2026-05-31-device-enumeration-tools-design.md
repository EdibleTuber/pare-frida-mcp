# Device-level enumeration tools: `enumerate_processes` & `enumerate_applications`

**Date:** 2026-05-31
**Status:** Approved (design)

## Problem

The worker exposes no device-level tool for listing running processes or
installed applications. In a live PARE session, the driving model was asked to
"show me the processes running on the android emulator" and had no tool for it.
It improvised by trying to `attach` to a pseudo-target (`frida-ps`) and then
`execute_script` arbitrary JS — escalating from `high` to `critical` risk for
what should be a trivial read-only lookup.

The underlying Frida capability already exists in the codebase: `attach` calls
`device.enumerate_processes()` internally to resolve a process name to a pid
(`tools.py:59`). It is simply not exposed as a standalone tool.

## Goal

Expose two device-scoped, read-only enumeration tools so the agent can list
running processes and installed packages without attaching to anything.

## Design

### Tools

| Tool | Frida call | Risk | Inputs | Returns |
|---|---|---|---|---|
| `enumerate_processes` | `device.enumerate_processes()` | `low` | `device_id` (opt), `filter` (opt substring) | `processes: [{pid, name}]` |
| `enumerate_applications` | `device.enumerate_applications()` | `low` | `device_id` (opt), `filter` (opt substring) | `applications: [{identifier, name, pid}]` |

Both are **device-scoped** (`device_id`), not session-scoped (`session_id`).
This is the crux of the fix: they resolve a device via the existing
`devices_mod.get_device(device_id or None)` helper (same one `attach` and
`select_device` use, defaulting to the USB device), and never touch the session
manager or require a prior `attach`.

Risk tier is `low`, consistent with the other read-only enumerators
(`list_devices`, `enumerate_modules`, `enumerate_exports`).

### Layers (following existing seams)

1. **`core/devices.py`** — two pure functions:
   - `enumerate_processes(device, filter=None) -> list[dict]`
   - `enumerate_applications(device, filter=None) -> list[dict]`

   Each calls the Frida API, maps each object to a plain dict, and applies a
   case-insensitive substring `filter` (matched on `name`; also on `identifier`
   for applications). This keeps Frida-object→dict mapping in one place, the
   same way `enumerate_devices` already lives here. Adding fields later (e.g.
   `parameters`, `ppid`) is a one-line change here.

2. **`tools.py`** — two `async` handlers using the existing `_ok`/`_err`
   pattern. The summary reports the **true** count (e.g. `"183 processes"`)
   while the returned list is capped at 200, exactly like `enumerate_modules`
   (`tools.py:77`), so truncation is visible to the agent and `bound_text`
   still backstops the byte cap.

   ```python
   async def enumerate_processes(device_id: str = "", filter: str = "") -> str:
       try:
           d = devices_mod.get_device(device_id or None)
           procs = devices_mod.enumerate_processes(d, filter or None)
           return _ok(f"{len(procs)} processes", processes=procs[:200])
       except Exception as e:
           return _err("enumerate_processes failed", e)

   async def enumerate_applications(device_id: str = "", filter: str = "") -> str:
       try:
           d = devices_mod.get_device(device_id or None)
           apps = devices_mod.enumerate_applications(d, filter or None)
           return _ok(f"{len(apps)} applications", applications=apps[:200])
       except Exception as e:
           return _err("enumerate_applications failed", e)
   ```

3. **`contract.py`** — two `ToolSpec` entries:

   ```python
   ToolSpec("enumerate_processes", "low", "List running processes on a device.",
            _in(device_id={"type": "string"}, filter={"type": "string"})),
   ToolSpec("enumerate_applications", "low",
            "List installed applications/packages on a device.",
            _in(device_id={"type": "string"}, filter={"type": "string"})),
   ```

   Registration in `server.py` is automatic — it loops `TOOL_SPECS` and binds
   handlers by name — so **no server changes**.

### Output shape (lean by default)

- Processes: `{pid, name}`
- Applications: `{identifier, name, pid}` (`identifier` = package name; `pid` is
  0 when the app is not running)

Frida's `parameters` dict (ppid, user, app icons, etc.) is deliberately omitted
— bulky and noisy for an agent. This is extensible later without a redesign:
the output schema (`_BOUNDED_OUT`) is permissive and `bound_text` does not
validate field names, so adding keys needs no `CONTRACT_VERSION` bump and does
not break existing PARE flows. If richer output is wanted later, add an opt-in
`include_parameters` boolean input (default false).

### Error handling

Identical to the rest of `tools.py`: wrap in try/except, return a bounded
`_err(...)`. Devices that don't support a given call (e.g. the `local` system
device for `enumerate_applications`) raise, and that surfaces as a clean bounded
error rather than a crash.

## Testing

- **Unit** (`tests/unit/`, no device): feed the device-layer functions a fake
  device exposing `enumerate_processes`/`enumerate_applications` returning stub
  objects; assert dict shape, substring filtering, and case-insensitivity.
- **Contract:** no new test required — the existing dynamic conformance,
  list-tools, and risk-tier integration tests pick up the new specs
  automatically. Run them to confirm both tools advertise `low`.
- **Device** (`tests/device/test_android_flows.py`, emulator-gated): add an
  `enumerate_processes(filter=...)` assertion against `emulator-5554`, alongside
  the existing module-enumeration flow.

## Out of scope

- `parameters` / icon data in output (extensible later, see above).
- Spawning/killing processes; this is read-only enumeration only.
