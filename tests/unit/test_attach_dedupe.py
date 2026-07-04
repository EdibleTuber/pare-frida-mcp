"""attach() reuses an existing live session for the same (device, pid) instead
of minting a duplicate.

Before: `/attach 3899` always created a new frida session + bundled script even
when one was already attached to pid 3899 -> two live sessions per pid, forcing
the model to disambiguate. Dedupe key is (device_id, pid): a pid is only unique
within a device.
"""
import json

import pytest

from pare_frida_mcp import tools as T
from pare_frida_mcp.config import Config
from pare_frida_mcp.core import devices as devices_mod
from pare_frida_mcp.core import scripts as scripts_mod
from pare_frida_mcp.core.sessions import SessionManager
from pare_frida_mcp.ids import new_session_id


def _cfg(tmp_path):
    return Config(capture_dir=tmp_path, max_tool_bytes=4096,
                  blob_threshold=65536, max_disk_per_session=10**9)


class _FakeScript:
    def on(self, event, cb):
        pass


class _FakeFridaSession:
    def __init__(self, detached=False):
        self.is_detached = detached


# --- SessionManager.find_live_session ----------------------------------------

def test_find_live_session_matches_device_and_pid(tmp_path):
    mgr = SessionManager(_cfg(tmp_path))
    sid = mgr.register_session(script=_FakeScript(), pid=3899, name="com.x",
                               device_id="emulator-5554")
    mgr.get(sid).frida_session = _FakeFridaSession(detached=False)
    assert mgr.find_live_session(3899, "emulator-5554") == sid


def test_find_live_session_skips_dead_session(tmp_path):
    mgr = SessionManager(_cfg(tmp_path))
    sid = mgr.register_session(script=_FakeScript(), pid=3899, name="com.x",
                               device_id="emulator-5554")
    mgr.get(sid).frida_session = _FakeFridaSession(detached=True)   # process gone
    assert mgr.find_live_session(3899, "emulator-5554") is None


def test_find_live_session_different_pid_is_none(tmp_path):
    mgr = SessionManager(_cfg(tmp_path))
    sid = mgr.register_session(script=_FakeScript(), pid=3899, name="com.x",
                               device_id="emulator-5554")
    mgr.get(sid).frida_session = _FakeFridaSession(detached=False)
    assert mgr.find_live_session(1234, "emulator-5554") is None


def test_find_live_session_different_device_is_none(tmp_path):
    """Same pid on a different device must NOT match — pids aren't global."""
    mgr = SessionManager(_cfg(tmp_path))
    sid = mgr.register_session(script=_FakeScript(), pid=3899, name="com.x",
                               device_id="emulator-5554")
    mgr.get(sid).frida_session = _FakeFridaSession(detached=False)
    assert mgr.find_live_session(3899, "usb-phone") is None


# --- attach() tool: reuse vs create ------------------------------------------

class _FakeDevice:
    def __init__(self, dev_id="emulator-5554"):
        self.id = dev_id
        self.attach_calls = []

    def attach(self, pid):
        self.attach_calls.append(pid)
        return _FakeFridaSession(detached=False)

    def enumerate_processes(self):
        return []


@pytest.mark.asyncio
async def test_attach_reuses_existing_live_session(monkeypatch, tmp_path):
    dev = _FakeDevice("emulator-5554")
    monkeypatch.setattr(devices_mod, "get_device", lambda _id: dev)
    # a live session already attached to pid 3899 on this device
    sid = T.MANAGER.register_session(script=_FakeScript(), pid=3899, name="com.x",
                                     device_id="emulator-5554")
    T.MANAGER.get(sid).frida_session = _FakeFridaSession(detached=False)
    try:
        doc = json.loads(await T.attach("3899"))
        assert doc.get("error") is not True, doc
        assert doc["session_id"] == sid          # SAME session, not a new one
        assert doc["reused"] is True
        assert dev.attach_calls == []            # no second frida attach
    finally:
        T.MANAGER._sessions.pop(sid, None)


@pytest.mark.asyncio
async def test_attach_creates_when_no_live_session(monkeypatch, tmp_path):
    dev = _FakeDevice("emulator-5554")
    monkeypatch.setattr(devices_mod, "get_device", lambda _id: dev)
    monkeypatch.setattr(scripts_mod, "load_bundled_script", lambda fs: _FakeScript())
    created = None
    try:
        doc = json.loads(await T.attach("4242"))
        assert doc.get("error") is not True, doc
        assert doc["reused"] is False
        assert dev.attach_calls == [4242]        # a real attach happened
        created = doc["session_id"]
        assert T.MANAGER.find_live_session(4242, "emulator-5554") == created
    finally:
        if created:
            T.MANAGER._sessions.pop(created, None)
