import json
import pytest
from pare_frida_mcp import tools as T


@pytest.mark.asyncio
async def test_list_devices_includes_emulator():
    res = json.loads(await T.list_devices())
    ids = {d["id"] for d in res.get("devices", [])}
    assert "emulator-5554" in ids


@pytest.mark.asyncio
async def test_attach_enumerate_read(system_server_pid):
    res = json.loads(await T.attach(target=str(system_server_pid)))
    assert "session_id" in res, res
    sid = res["session_id"]
    try:
        mods = json.loads(await T.enumerate_modules(sid, filter="libc"))
        assert mods.get("modules"), mods
        libc = next((m for m in mods["modules"] if "libc" in m["name"]), None)
        assert libc is not None
        mem = json.loads(await T.read_memory(sid, address=libc["base"], size=16))
        assert mem.get("hex_preview"), mem
    finally:
        # Detach via the underlying frida session to free emulator resources.
        T.MANAGER.get(sid).frida_session.detach()


@pytest.mark.asyncio
async def test_java_hook_install(system_server_pid):
    res = json.loads(await T.attach(target=str(system_server_pid)))
    sid = res["session_id"]
    try:
        hook = json.loads(await T.java_hook(sid, cls="java.lang.System", method="currentTimeMillis"))
        assert hook.get("hook"), hook
    finally:
        T.MANAGER.get(sid).frida_session.detach()
