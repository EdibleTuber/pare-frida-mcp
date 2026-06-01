import json
import pytest

from pare_frida_mcp import tools as T
from pare_frida_mcp.capture.store import CaptureStore
from pare_frida_mcp.core.snapshots import SNAPSHOT_HANDLE
from pare_frida_mcp.ids import new_session_id


class DummySession:
    def __init__(self, store):
        self.store = store
        self.flushed = False

    def flush(self):
        self.flushed = True


def test_resolve_store_routes_snapshot_handle():
    store, s = T._resolve_store(SNAPSHOT_HANDLE)
    assert store is T.SNAPSHOTS.store
    assert s is None


def test_resolve_store_routes_session_id():
    sid = new_session_id()
    dummy = DummySession(CaptureStore.open_memory())
    T.MANAGER._sessions[sid] = dummy
    try:
        store, s = T._resolve_store(sid)
        assert store is dummy.store
        assert s is dummy
    finally:
        T.MANAGER._sessions.pop(sid, None)


@pytest.mark.asyncio
async def test_search_capture_reads_snapshots_without_session():
    T.SNAPSHOTS.replace("enumerate_processes:device_id=D",
                        [{"pid": 1, "name": "zygote"}, {"pid": 2, "name": "system_server"}])
    res = json.loads(await T.search_capture(SNAPSHOT_HANDLE, text="zygote"))
    assert res["total"] == 1, res
    assert res.get("error") is not True


@pytest.mark.asyncio
async def test_read_capture_reads_snapshot_row_without_session():
    T.SNAPSHOTS.replace("enumerate_processes:device_id=E", [{"pid": 7, "name": "soloproc"}])
    found = json.loads(await T.search_capture(SNAPSHOT_HANDLE, field="source",
                                              contains="device_id=E"))
    seq = found["matches"][0]["seq"]
    res = json.loads(await T.read_capture(SNAPSHOT_HANDLE, seq=seq))
    assert "soloproc" in res["text"], res
