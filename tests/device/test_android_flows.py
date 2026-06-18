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
        assert mods["store"] == "@snapshots", mods
        assert mods["total"] > 50, mods            # full list persisted, uncapped
        # Recover libc's base from the snapshot via a NARROW search (the
        # intended persist-then-search usage), then read its memory.
        found = json.loads(await T.search_capture("@snapshots", text="libc"))
        assert found["total"] >= 1, found
        libc = next((p for p in (json.loads(m["payload"]) for m in found["matches"])
                     if "libc" in p["name"]), None)
        assert libc is not None, found
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


@pytest.mark.asyncio
async def test_enumerate_processes_on_emulator(usb_device):
    res = json.loads(await T.enumerate_processes(device_id="emulator-5554"))
    assert res["total"] >= 1, res
    # Retrieve via a NARROW search (the intended persist-then-search usage). A
    # broad source-key dump of the whole snapshot can exceed the tool byte cap;
    # the model is expected to search for what it needs. 'zygote' is the Android
    # app-process spawner and is present on every emulator image.
    found = json.loads(await T.search_capture("@snapshots", text="zygote"))
    assert found["total"] >= 1, found
    assert any("zygote" in m["payload"] for m in found["matches"]), found


@pytest.mark.asyncio
async def test_enumerate_applications_on_emulator(usb_device):
    res = json.loads(await T.enumerate_applications(device_id="emulator-5554"))
    assert res["total"] >= 1, res
    # The Android settings package is present on every emulator image.
    found = json.loads(await T.search_capture("@snapshots", text="settings"))
    assert found["total"] >= 1, found
