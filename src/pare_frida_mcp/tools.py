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


def _ok(summary: str, **extra: Any) -> str:
    """Return the full JSON result envelope. No byte cap: bounding the model's
    context window is now the host's (PARE's) job, applied at the wire."""
    return json.dumps({"summary": summary, **extra})


def _err(summary: str, exc: Exception | None = None) -> str:
    payload = {"summary": summary, "error": True}
    if exc is not None:
        payload["detail"] = str(exc)
    return json.dumps(payload)


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
        res = scripts_mod.execute_ad_hoc(s.frida_session, source)
        if res["error"]:
            return _ok(f"script error: {res['error']}",
                       sends=res["sends"], logs=res["logs"], error=res["error"])
        return _ok(f"eval complete: {len(res['sends'])} send(s), {len(res['logs'])} log(s)",
                   sends=res["sends"], logs=res["logs"], error=None)
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


