from __future__ import annotations

import json
from typing import Any

from pare_frida_mcp.config import load_config
from pare_frida_mcp.core.sessions import Session, SessionManager
from pare_frida_mcp.core import devices as devices_mod
from pare_frida_mcp.core import scripts as scripts_mod
from pare_frida_mcp.core import memory as memory_mod
from pare_frida_mcp.android import java as java_mod
from pare_frida_mcp.capture.search import search_capture as _search_capture
from pare_frida_mcp.capture.read import read_capture as _read_capture
from pare_frida_mcp.capture.page import page_rows as _page_rows, list_sources as _list_sources
from pare_frida_mcp.capture.store import CaptureStore
from pare_frida_mcp.core.snapshots import SnapshotStore, SNAPSHOT_HANDLE, snapshot_key
from pare_frida_mcp.ids import validate_session_id

CFG = load_config()
MANAGER = SessionManager(CFG)
SNAPSHOTS = SnapshotStore()
_CAP = CFG.max_tool_bytes
# page_capture is consumed by the /snapshot command, NOT model context, so it
# is exempt from the 4096-byte model cap. Bound to a generous budget instead.
_PAGE_BUDGET = 262144


def _ok(summary: str, **extra: Any) -> str:
    """Return the full JSON result envelope. No byte cap: bounding the model's
    context window is now the host's (PARE's) job, applied at the wire."""
    return json.dumps({"summary": summary, **extra})


def _err(summary: str, exc: Exception | None = None) -> str:
    payload = {"summary": summary, "error": True}
    if exc is not None:
        payload["detail"] = str(exc)
    return json.dumps(payload)


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


async def list_sessions() -> str:
    try:
        rows = MANAGER.list_sessions()
        return _ok(f"{len(rows)} sessions", sessions=rows)
    except Exception as e:
        return _err("list_sessions failed", e)


async def detach(session_id: str) -> str:
    try:
        sid = validate_session_id(session_id)
        MANAGER.detach(sid)
        # A torn-down session's module/export snapshots must not linger
        # queryable (stale == wrong). Re-attach starts fresh snapshots.
        SNAPSHOTS.delete_sessions(sid)
        return _ok(f"detached {sid}", session_id=sid)
    except KeyError:
        return _err(f"no such session {session_id!r}")
    except Exception as e:
        return _err("detach failed", e)


async def enumerate_processes(device_id: str = "") -> str:
    try:
        d = devices_mod.get_device(device_id or None)
        items = devices_mod.enumerate_processes(d)
        return _ok(f"{len(items)} processes", processes=items)
    except Exception as e:
        return _err("enumerate_processes failed", e)


async def enumerate_applications(device_id: str = "") -> str:
    try:
        d = devices_mod.get_device(device_id or None)
        if getattr(d, "type", None) == "local":
            return _ok("application enumeration not supported on device type "
                       "'local' - use enumerate_processes", applications=[])
        items = devices_mod.enumerate_applications(d)
        return _ok(f"{len(items)} applications", applications=items)
    except Exception as e:
        return _err("enumerate_applications failed", e)


async def enumerate_modules(session_id: str) -> str:
    try:
        sid = validate_session_id(session_id)
        s = MANAGER.get(sid)
        mods = memory_mod.enumerate_modules(s.script)
        return _ok(f"{len(mods)} modules", modules=mods)
    except Exception as e:
        return _err("enumerate_modules failed", e)


async def enumerate_exports(session_id: str, module: str) -> str:
    try:
        sid = validate_session_id(session_id)
        s = MANAGER.get(sid)
        exps = memory_mod.enumerate_exports(s.script, module)
        return _ok(f"{len(exps)} exports for {module}", exports=exps)
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
        return _ok("eval complete", result=value)
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
        n = len(data) if data else 0
        return _ok(f"read {n} bytes @ {address}",
                   address=address, size=size, bytes=n, hex=data.hex() if data else "")
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


async def page_capture(session_id: str, source: str = "", field: str = "",
                       contains: str = "", list_sources: bool = False) -> str:
    try:
        store, _ = _resolve_store(session_id)
        if list_sources:
            srcs = _list_sources(store)
            return json.dumps({"summary": f"{len(srcs)} snapshots",
                               "store": session_id, "sources": srcs})
        # Latest resolution is @snapshots-specific (MRU); v0 only uses @snapshots.
        src = source or (SNAPSHOTS.latest_source() if session_id == SNAPSHOT_HANDLE else "")
        if not src:
            return json.dumps({"summary": "no snapshots captured yet",
                               "store": session_id, "sources": []})
        res = _page_rows(store, source=src, field=field or None,
                         contains=contains or None, byte_budget=_PAGE_BUDGET)
        summary = f"{res['shown']} of {res['total']} rows for {src}"
        # Direct json.dumps (NOT _ok): intentionally bypasses the model cap.
        return json.dumps({"summary": summary, "store": session_id, "source": src,
                           "rows": res["rows"], "total": res["total"],
                           "shown": res["shown"]})
    except Exception as e:
        return _err("page_capture failed", e)
