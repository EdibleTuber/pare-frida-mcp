import json

import pytest

from pare_frida_mcp import tools as T
from pare_frida_mcp.capture.store import CaptureStore
from pare_frida_mcp.ids import new_session_id


class _FakeFridaSession:
    def __init__(self, detached=False):
        self.is_detached = detached
        self.detached_calls = 0

    def detach(self):
        self.detached_calls += 1
        self.is_detached = True


class _FakeSession:
    """Mirrors the attrs SessionManager.list_sessions/detach read off a Session."""

    def __init__(self, sid, pid, name, fs):
        self.id = sid
        self.pid = pid
        self.name = name
        self.frida_session = fs
        self.store = CaptureStore.open_memory()
        self.flushed = False

    def flush(self):
        self.flushed = True


@pytest.mark.asyncio
async def test_list_sessions_empty():
    res = json.loads(await T.list_sessions())
    assert res.get("error") is not True
    assert res["sessions"] == []


@pytest.mark.asyncio
async def test_list_sessions_reports_liveness():
    sid_live, sid_dead = new_session_id(), new_session_id()
    T.MANAGER._sessions[sid_live] = _FakeSession(sid_live, 100, "com.live", _FakeFridaSession(False))
    T.MANAGER._sessions[sid_dead] = _FakeSession(sid_dead, 200, "com.dead", _FakeFridaSession(True))
    try:
        res = json.loads(await T.list_sessions())
        by_id = {r["session_id"]: r for r in res["sessions"]}
        assert by_id[sid_live]["live"] is True
        assert by_id[sid_live]["pid"] == 100 and by_id[sid_live]["name"] == "com.live"
        assert by_id[sid_dead]["live"] is False
    finally:
        T.MANAGER._sessions.pop(sid_live, None)
        T.MANAGER._sessions.pop(sid_dead, None)


@pytest.mark.asyncio
async def test_list_sessions_none_frida_session_is_not_live():
    sid = new_session_id()
    T.MANAGER._sessions[sid] = _FakeSession(sid, 1, "x", None)
    try:
        res = json.loads(await T.list_sessions())
        assert res["sessions"][0]["live"] is False
    finally:
        T.MANAGER._sessions.pop(sid, None)
