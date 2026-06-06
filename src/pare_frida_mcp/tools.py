from __future__ import annotations

import json
from typing import Any

from pare_frida_mcp.bounding import bound_text, fit_items
from pare_frida_mcp.config import load_config
from pare_frida_mcp.core.sessions import Session, SessionManager
from pare_frida_mcp.core import devices as devices_mod
from pare_frida_mcp.core import scripts as scripts_mod
from pare_frida_mcp.core import memory as memory_mod
from pare_frida_mcp.android import java as java_mod
from pare_frida_mcp.capture.search import search_capture as _search_capture
from pare_frida_mcp.capture.read import read_capture as _read_capture
from pare_frida_mcp.capture.store import CaptureStore
from pare_frida_mcp.core.snapshots import SnapshotStore, SNAPSHOT_HANDLE, snapshot_key
from pare_frida_mcp.ids import validate_session_id

CFG = load_config()
MANAGER = SessionManager(CFG)
SNAPSHOTS = SnapshotStore()
_CAP = CFG.max_tool_bytes


def _ok(summary: str, **extra: Any) -> str:
    payload = {"summary": summary, **extra}
    blob = json.dumps(payload)
    if len(blob.encode("utf-8")) <= _CAP:
        return blob
    # Too large to inline. Return a VALID fallback envelope rather than a
    # byte-truncated (invalid-JSON) string. Tools that pre-bound their output
    # never reach here; this is the universal floor for those that don't.
    short, _ = bound_text(summary, 512)
    return json.dumps({
        "summary": short,
        "truncated": True,
        "error": "result too large to inline; narrow the query or use "
                 "search_capture/read_capture",
    })


def _err(summary: str, exc: BaseException | None = None) -> str:
    payload = {"summary": summary, "error": True}
    if exc is not None:
        payload["detail"] = f"{type(exc).__name__}: {exc}"
    blob = json.dumps(payload)
    if len(blob.encode("utf-8")) <= _CAP:
        return blob
    short, _ = bound_text(summary, 512)
    detail, _ = bound_text(payload.get("detail", ""), _CAP // 2)
    return json.dumps({"summary": short, "error": True, "detail": detail})


def _resolve_store(handle: str) -> tuple[CaptureStore, Session | None]:
    """Return (store, session). For the reserved snapshot handle, session is
    None (no pending queue to flush); otherwise resolve the session store."""
    if handle == SNAPSHOT_HANDLE:
        return SNAPSHOTS.store, None
    sid = validate_session_id(handle)
    s = MANAGER.get(sid)
    return s.store, s


async def list_devices() -> str:
    try:
        devs = devices_mod.enumerate_devices()
        return _ok(f"{len(devs)} devices", devices=devs)
    except Exception as e:
        return _err("list_devices failed", e)


async def select_device(device_id: str) -> str:
    try:
        d = devices_mod.get_device(device_id)
        return _ok(f"selected {d.name}", id=d.id, name=d.name, type=d.type)
    except Exception as e:
        return _err("select_device failed", e)


async def attach(target: str = "", device_id: str = "") -> str:
    try:
        d = devices_mod.get_device(device_id or None)
        if target.isdigit():
            pid = int(target)
            name = str(pid)
        else:
            matches = [p for p in d.enumerate_processes() if p.name == target]
            if not matches:
                return _err(f"process {target!r} not found")
            pid, name = matches[0].pid, matches[0].name
        fsession = d.attach(pid)
        script = scripts_mod.load_bundled_script(fsession)
        sid = MANAGER.register_session(script=script, pid=pid, name=name)
        MANAGER.get(sid).frida_session = fsession
        return _ok(f"attached pid {pid}", session_id=sid, pid=pid, name=name)
    except Exception as e:
        return _err("attach failed", e)


async def enumerate_processes(device_id: str = "") -> str:
    try:
        d = devices_mod.get_device(device_id or None)
        items = devices_mod.enumerate_processes(d)
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


async def enumerate_modules(session_id: str, filter: str = "") -> str:
    try:
        sid = validate_session_id(session_id)
        s = MANAGER.get(sid)
        mods = memory_mod.enumerate_modules(s.script, filter or None)
        shown, fully = fit_items(mods, _CAP)
        note = "" if fully else f" (showing {len(shown)}; narrow with filter=)"
        return _ok(f"{len(mods)} modules{note}",
                   modules=shown, total=len(mods), truncated=not fully)
    except Exception as e:
        return _err("enumerate_modules failed", e)


async def enumerate_exports(session_id: str, module: str) -> str:
    try:
        sid = validate_session_id(session_id)
        s = MANAGER.get(sid)
        exps = memory_mod.enumerate_exports(s.script, module)
        shown, fully = fit_items(exps, _CAP)
        note = "" if fully else f" (showing {len(shown)} of {len(exps)})"
        return _ok(f"{len(exps)} exports for {module}{note}",
                   exports=shown, total=len(exps), truncated=not fully)
    except Exception as e:
        return _err("enumerate_exports failed", e)


async def load_script(session_id: str, name: str = "") -> str:
    # v1: bundled script is loaded on attach; this tool reports current state.
    try:
        sid = validate_session_id(session_id)
        s = MANAGER.get(sid)
        return _ok("bundled script already loaded at attach", script_id=str(id(s.script)))
    except Exception as e:
        return _err("load_script failed", e)


async def execute_script(session_id: str, source: str) -> str:
    try:
        sid = validate_session_id(session_id)
        s = MANAGER.get(sid)
        value = scripts_mod.execute_ad_hoc(s.frida_session, source)
        # §4.1: every return path is bounded, including arbitrary eval results.
        # If the value fits the cap, return it inline; otherwise spill the full
        # result into the capture store and hand back a capture handle so the
        # agent can retrieve it via read_capture.
        # Probe the actual inline envelope shape (_ok adds a summary key), so the
        # spill decision matches what _ok will emit. Measuring a smaller shape
        # would let a value that fits {"value": ...} but not the _ok envelope slip
        # through and be dropped by _ok's oversized fallback.
        full = json.dumps({"summary": "eval complete", "result": value})
        _, truncated = bound_text(full, _CAP)
        if not truncated:
            return _ok("eval complete", result=value)
        seq = s.store.write({
            "type": "send",
            "source": "execute_script",
            "summary": "eval result spilled (too large for inline return)",
            "payload": {"value": value},
        })
        return _ok("eval complete (spilled)",
                   capture={"session_id": sid, "seq": seq})
    except Exception as e:
        return _err("execute_script failed", e)


async def java_hook(session_id: str, cls: str, method: str, overload: str = "") -> str:
    try:
        sid = validate_session_id(session_id)
        s = MANAGER.get(sid)
        res = java_mod.java_hook(s.script, cls, method, overload or None)
        return _ok(f"hook installed: {cls}.{method}", hook=res)
    except Exception as e:
        return _err("java_hook failed", e)


async def java_hook_remove(session_id: str, cls: str, method: str, overload: str = "") -> str:
    try:
        sid = validate_session_id(session_id)
        s = MANAGER.get(sid)
        res = s.script.exports_sync.java_hook_remove(cls, method, overload or "")
        return _ok(f"hook removed: {cls}.{method}", removed=res)
    except Exception as e:
        return _err("java_hook_remove failed", e)


async def read_memory(session_id: str, address: str, size: int) -> str:
    try:
        sid = validate_session_id(session_id)
        s = MANAGER.get(sid)
        data = memory_mod.read_memory(s.script, address, size)
        preview = data[:64].hex() if data else ""
        return _ok(f"read {len(data) if data else 0} bytes",
                   address=address, size=size, hex_preview=preview)
    except Exception as e:
        return _err("read_memory failed", e)


async def write_memory(session_id: str, address: str, bytes: str) -> str:
    try:
        sid = validate_session_id(session_id)
        s = MANAGER.get(sid)
        res = memory_mod.write_memory(s.script, address, bytes)
        return _ok(f"wrote {res.get('written', 0)} bytes", address=address)
    except Exception as e:
        return _err("write_memory failed", e)


async def search_capture(session_id: str, field: str = "", contains: str = "",
                         text: str = "", byte_budget: int = 0,
                         limit: int = 0, count_only: bool = False) -> str:
    try:
        store, s = _resolve_store(session_id)
        if s is not None:
            s.flush()  # ensure pending messages are persisted before searching
        # Clamp to _CAP: a caller-supplied budget above the cap would let the
        # engine fill past what _ok can emit, tripping _ok's fallback and
        # dropping every match instead of returning a bounded page.
        budget = min(byte_budget or _CAP, _CAP)
        if count_only:
            res = _search_capture(store, field=field or None, contains=contains or None,
                                  text=text or None, count_only=True)
            return _ok(f"{res['total']} matches (count only). Add text= terms to "
                       f"narrow, or search again without count_only to sample.",
                       total=res["total"], count_only=True)
        res = _search_capture(store, field=field or None, contains=contains or None,
                              text=text or None, limit=limit or 50, byte_budget=budget)
        if not res["truncated"]:
            summary = f"{res['total']} matches"
        elif res["sampled"]:
            summary = (f"{res['total']} matches - showing a {res['returned']}-row spread "
                       f"sample. Narrow with a more specific text=, or "
                       f"read_capture(seq=...) for one record.")
        else:
            summary = (f"{res['total']} matches - showing first {res['returned']} "
                       f"(output capped). Narrow with a more specific text=, or "
                       f"read_capture(seq=...) for one record.")
        return _ok(summary, **res)
    except Exception as e:
        return _err("search_capture failed", e)


async def read_capture(session_id: str, seq: int, offset: int = 0, byte_budget: int = 0) -> str:
    try:
        store, s = _resolve_store(session_id)
        if s is not None:
            s.flush()
        # Clamp to _CAP, then reserve headroom for the _ok envelope so the
        # wrapped {summary, seq, offset, truncated, next_offset, text} payload
        # stays under the cap and never trips _ok's data-dropping fallback.
        budget = max(1, min(byte_budget or _CAP, _CAP) - 512)
        res = _read_capture(store, seq=seq, offset=offset, byte_budget=budget)
        return _ok(f"seq {seq}", **res)
    except Exception as e:
        return _err("read_capture failed", e)
