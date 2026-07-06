from __future__ import annotations

import json
from typing import Any

from pare_frida_mcp.config import load_config
from pare_frida_mcp.core.sessions import Session, SessionManager
from pare_frida_mcp.core import devices as devices_mod
from pare_frida_mcp.core import scripts as scripts_mod
from pare_frida_mcp.core import memory as memory_mod
from pare_frida_mcp.android import java as java_mod
from pare_frida_mcp.ids import validate_session_id

CFG = load_config()
MANAGER = SessionManager(CFG)
_CAP = CFG.max_tool_bytes
_CLASS_CAP = 500  # mirrors the slice(0, 500) in agent/src/index.ts javaEnumerate
_EVENT_LIMIT_MAX = 500
_EVENT_WIRE_BUDGET = 3072   # below host max_tool_bytes so a normal read never trips the stub


def _clamp(v: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, v))


def _ok(summary: str, **extra: Any) -> str:
    """Return the full JSON result envelope. No byte cap: bounding the model's
    context window is now the host's (PARE's) job, applied at the wire."""
    return json.dumps({"summary": summary, **extra})


def _err(summary: str, exc: Exception | None = None) -> str:
    payload = {"summary": summary, "error": True}
    if exc is not None:
        payload["detail"] = str(exc)
    return json.dumps(payload)


def _resolve_session(session_id: str) -> Session:
    """Return the target Session. When session_id is given, validate + look it up;
    when omitted, fall back to the most-recent live session so the caller needn't
    restate the id it just got from attach. Raises with an attach hint when
    nothing is live."""
    if session_id:
        return MANAGER.get(validate_session_id(session_id))
    active = MANAGER.active_session()
    if active is None:
        raise LookupError("no session_id given and no live session - attach first")
    return MANAGER.get(active)


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
        dev_id = getattr(d, "id", None)
        existing = MANAGER.find_live_session(pid, dev_id)
        if existing is not None:
            es = MANAGER.get(existing)
            return _ok(f"reusing live session for pid {pid}", session_id=existing,
                       pid=pid, name=es.name, reused=True)
        fsession = d.attach(pid)
        script = scripts_mod.load_bundled_script(fsession)
        sid = MANAGER.register_session(script=script, pid=pid, name=name,
                                       device_id=dev_id)
        MANAGER.get(sid).frida_session = fsession
        return _ok(f"attached pid {pid}", session_id=sid, pid=pid, name=name,
                   reused=False)
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


async def enumerate_modules(session_id: str = "") -> str:
    try:
        s = _resolve_session(session_id)
        mods = memory_mod.enumerate_modules(s.script)
        return _ok(f"{len(mods)} modules", modules=mods)
    except Exception as e:
        return _err("enumerate_modules failed", e)


async def enumerate_exports(module: str, session_id: str = "") -> str:
    try:
        s = _resolve_session(session_id)
        exps = memory_mod.enumerate_exports(s.script, module)
        return _ok(f"{len(exps)} exports for {module}", exports=exps)
    except Exception as e:
        return _err("enumerate_exports failed", e)


async def enumerate_classes(filter: str = "", session_id: str = "") -> str:
    try:
        s = _resolve_session(session_id)
        rows = java_mod.enumerate_classes(s.script, filter)
        note = " (capped - refine the filter to see more)" if len(rows) >= _CLASS_CAP else ""
        return _ok(f"{len(rows)} classes{note}", classes=rows)
    except Exception as e:
        return _err("enumerate_classes failed", e)


async def enumerate_methods(cls: str, session_id: str = "") -> str:
    try:
        s = _resolve_session(session_id)
        rows = java_mod.enumerate_methods(s.script, cls)
        return _ok(f"{len(rows)} methods for {cls}", methods=rows)
    except Exception as e:
        return _err("enumerate_methods failed", e)


async def load_script(name: str = "", session_id: str = "") -> str:
    # v1: bundled script is loaded on attach; this tool reports current state.
    try:
        s = _resolve_session(session_id)
        return _ok("bundled script already loaded at attach", script_id=str(id(s.script)))
    except Exception as e:
        return _err("load_script failed", e)


async def execute_script(source: str, session_id: str = "") -> str:
    try:
        s = _resolve_session(session_id)
        res = scripts_mod.execute_ad_hoc(s.frida_session, source)
        if res["error"]:
            return _ok(f"script error: {res['error']}",
                       sends=res["sends"], logs=res["logs"], error=res["error"])
        return _ok(f"eval complete: {len(res['sends'])} send(s), {len(res['logs'])} log(s)",
                   sends=res["sends"], logs=res["logs"], error=None)
    except Exception as e:
        return _err("execute_script failed", e)


async def java_hook(cls: str, method: str, overload: str = "", session_id: str = "") -> str:
    try:
        s = _resolve_session(session_id)
        res = java_mod.java_hook(s.script, cls, method, overload or None)
        return _ok(f"hook installed: {cls}.{method}", hook=res)
    except Exception as e:
        return _err("java_hook failed", e)


async def java_hook_remove(cls: str, method: str, overload: str = "", session_id: str = "") -> str:
    try:
        s = _resolve_session(session_id)
        res = s.script.exports_sync.java_hook_remove(cls, method, overload or "")
        return _ok(f"hook removed: {cls}.{method}", removed=res)
    except Exception as e:
        return _err("java_hook_remove failed", e)


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


async def read_memory(address: str, size: int, session_id: str = "") -> str:
    try:
        s = _resolve_session(session_id)
        data = memory_mod.read_memory(s.script, address, size)
        n = len(data) if data else 0
        return _ok(f"read {n} bytes @ {address}",
                   address=address, size=size, bytes=n, hex=data.hex() if data else "")
    except Exception as e:
        return _err("read_memory failed", e)


async def write_memory(address: str, bytes: str, session_id: str = "") -> str:
    try:
        s = _resolve_session(session_id)
        res = memory_mod.write_memory(s.script, address, bytes)
        return _ok(f"wrote {res.get('written', 0)} bytes", address=address)
    except Exception as e:
        return _err("write_memory failed", e)


