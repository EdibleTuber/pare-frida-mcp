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
        mods = json.loads(await T.enumerate_modules(sid))
        assert len(mods["modules"]) > 50, mods    # full list returned directly
        # Find libc directly in the returned list
        libc = next((m for m in mods["modules"] if "libc" in m["name"]), None)
        assert libc is not None, mods
        mem = json.loads(await T.read_memory(address=libc["base"], size=16, session_id=sid))
        assert mem.get("hex"), mem
    finally:
        # Detach via the underlying frida session to free emulator resources.
        T.MANAGER.get(sid).frida_session.detach()


@pytest.mark.asyncio
async def test_java_hook_install(system_server_pid):
    res = json.loads(await T.attach(target=str(system_server_pid)))
    sid = res["session_id"]
    try:
        hook = json.loads(await T.java_hook(cls="java.lang.System", method="currentTimeMillis", session_id=sid))
        assert hook.get("hook"), hook
    finally:
        T.MANAGER.get(sid).frida_session.detach()


@pytest.mark.asyncio
async def test_enumerate_processes_on_emulator(usb_device):
    res = json.loads(await T.enumerate_processes(device_id="emulator-5554"))
    # 'zygote' is the Android app-process spawner, present on every emulator image.
    assert len(res["processes"]) >= 1, res
    assert any("zygote" in p["name"] for p in res["processes"]), res


@pytest.mark.asyncio
async def test_enumerate_applications_on_emulator(usb_device):
    res = json.loads(await T.enumerate_applications(device_id="emulator-5554"))
    # The Android settings package is present on every emulator image.
    assert len(res["applications"]) >= 1, res
    assert any("settings" in a.get("identifier", "") for a in res["applications"]), res
