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


OMTG_APP = "sg.vp.owasp_mobile.omtg_android"
OMTG_MEM = "sg.vp.owasp_mobile.OMTG_Android.OMTG_DATAST_011_Memory"


async def _attach_omtg():
    res = json.loads(await T.attach(target=OMTG_APP))
    if "session_id" not in res:
        pytest.skip(f"OMTG app not attachable: {res.get('summary')}")
    return res["session_id"]


@pytest.mark.asyncio
async def test_read_fields_recovers_plaintext_in_one_call():
    """Root-cause falsification: after the operator triggers decryptString on the
    OMTG_DATAST_011_Memory screen, one java_read_fields call returns plainText."""
    sid = await _attach_omtg()
    try:
        input(f"\n[operator] open '{OMTG_MEM}' in the app, then press Enter...")
        doc = json.loads(await T.java_read_fields(cls=OMTG_MEM, fields=["plainText"], session_id=sid))
        assert doc.get("error") is not True, doc
        vals = [i["fields"].get("plainText") for i in doc.get("instances", [])]
        assert any(isinstance(v, str) and v for v in vals), doc     # non-empty plaintext recovered
    finally:
        T.MANAGER.get(sid).frida_session.detach()


@pytest.mark.asyncio
async def test_read_fields_dump_all_finds_plaintext():
    """Omitting fields dumps declared fields; plainText appears among them."""
    sid = await _attach_omtg()
    try:
        input(f"\n[operator] open '{OMTG_MEM}' in the app, then press Enter...")
        doc = json.loads(await T.java_read_fields(cls=OMTG_MEM, session_id=sid))
        assert doc.get("error") is not True, doc
        assert any("plainText" in i.get("fields", {}) for i in doc.get("instances", [])), doc
    finally:
        T.MANAGER.get(sid).frida_session.detach()


@pytest.mark.asyncio
async def test_capture_this_snapshots_plaintext_at_hook_site():
    """capture_this on decryptString surfaces this.plainText via read_hook_events."""
    sid = await _attach_omtg()
    try:
        hook = json.loads(await T.java_hook(cls=OMTG_MEM, method="decryptString",
                                            capture_this=["plainText"], session_id=sid))
        assert hook.get("hook"), hook
        input(f"\n[operator] open '{OMTG_MEM}' to trigger decryptString, then press Enter...")
        ev = json.loads(await T.read_hook_events(since_seq=0, session_id=sid))
        thises = [e.get("this", {}).get("plainText") for e in ev.get("events", [])]
        assert any(isinstance(v, str) and v for v in thises), ev
    finally:
        T.MANAGER.get(sid).frida_session.detach()
