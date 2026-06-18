import json
import pytest

from pare_frida_mcp import tools as T
from pare_frida_mcp.core import memory as memory_mod
from pare_frida_mcp.capture.store import CaptureStore
from pare_frida_mcp.core.snapshots import snapshot_key
from pare_frida_mcp.ids import new_session_id


class _DummySession:
    """Minimal stand-in for a live Session: enough surface for the enumerate
    and detach handlers. frida_session=None so MANAGER.detach skips fs.detach;
    flush() is a no-op; store is a real in-memory CaptureStore."""
    def __init__(self):
        self.script = object()
        self.frida_session = None
        self.store = CaptureStore.open_memory()

    def flush(self):
        pass


@pytest.mark.asyncio
async def test_source_contains_escapes_like_metachars():
    # Two sources differing only at an underscore position. Unescaped, the '_'
    # in lib_x would also match libQx; with ESCAPE it must match only lib_x.
    T.SNAPSHOTS.replace("enumerate_exports:module=lib_x:session=s1", [{"name": "f1"}])
    T.SNAPSHOTS.replace("enumerate_exports:module=libQx:session=s1", [{"name": "f2"}])
    res = json.loads(await T.search_capture(
        "@snapshots", field="source",
        contains="enumerate_exports:module=lib_x:session=s1"))
    assert res["total"] == 1, res
    assert all("lib_x" in m["source"] for m in res["matches"]), res


from pare_frida_mcp.core.snapshots import SnapshotStore


def test_delete_sessions_purges_only_that_session():
    store = SnapshotStore()
    a = snapshot_key("enumerate_modules", session="sid-a")
    a_exp = snapshot_key("enumerate_exports", session="sid-a", module="libc.so")
    b = snapshot_key("enumerate_modules", session="sid-b")
    store.replace(a, [{"name": "libc.so"}])
    store.replace(a_exp, [{"name": "open"}])
    store.replace(b, [{"name": "libm.so"}])

    removed = store.delete_sessions("sid-a")

    assert removed == 2                      # a and a_exp, not b
    assert store.latest_source() == b        # only sid-b's key remains tracked

    def _count(source):
        return store.store._conn.execute(
            "SELECT count(*) c FROM messages WHERE source=?", (source,)).fetchone()["c"]
    assert _count(a) == 0 and _count(a_exp) == 0   # sid-a purged
    assert _count(b) == 1                            # sid-b survives


def test_delete_sessions_no_prefix_collision():
    store = SnapshotStore()
    s1 = snapshot_key("enumerate_modules", session="s1")
    s10 = snapshot_key("enumerate_modules", session="s10")
    store.replace(s1, [{"name": "a"}])
    store.replace(s10, [{"name": "b"}])
    removed = store.delete_sessions("s1")
    assert removed == 1                 # only s1, NOT s10
    assert store.latest_source() == s10


@pytest.mark.asyncio
async def test_enumerate_modules_handle_only(monkeypatch):
    sid = new_session_id()
    T.MANAGER._sessions[sid] = _DummySession()
    monkeypatch.setattr(memory_mod, "enumerate_modules",
                        lambda script: [{"name": f"lib{i}.so", "base": hex(i), "size": i}
                                        for i in range(300)])
    res = json.loads(await T.enumerate_modules(sid))
    assert res["store"] == "@snapshots", res
    assert res["total"] == 300, res
    assert "modules" not in res, res                 # handle-only, no inline list
    key = res["source"]
    assert key == snapshot_key("enumerate_modules", session=sid)
    got = json.loads(await T.search_capture("@snapshots", field="source",
                                            contains=key, count_only=True))
    assert got["total"] == 300, got


@pytest.mark.asyncio
async def test_enumerate_exports_handle_only(monkeypatch):
    sid = new_session_id()
    T.MANAGER._sessions[sid] = _DummySession()
    monkeypatch.setattr(memory_mod, "enumerate_exports",
                        lambda script, module: [{"name": f"sym{i}", "address": hex(i)}
                                                for i in range(120)])
    res = json.loads(await T.enumerate_exports(sid, module="libc.so"))
    assert res["store"] == "@snapshots", res
    assert res["total"] == 120, res
    assert "exports" not in res, res
    assert res["source"] == snapshot_key("enumerate_exports", session=sid, module="libc.so")


@pytest.mark.asyncio
async def test_detach_purges_session_snapshots():
    sid = new_session_id()
    T.MANAGER._sessions[sid] = _DummySession()
    key = snapshot_key("enumerate_modules", session=sid)
    other = snapshot_key("enumerate_modules", session="other-sid")
    T.SNAPSHOTS.replace(key, [{"name": "libc.so"}])
    T.SNAPSHOTS.replace(other, [{"name": "libm.so"}])

    res = json.loads(await T.detach(sid))
    assert res.get("session_id") == sid, res

    gone = json.loads(await T.search_capture("@snapshots", field="source",
                                             contains=key, count_only=True))
    assert gone["total"] == 0, gone
    survives = json.loads(await T.search_capture("@snapshots", field="source",
                                                 contains=other, count_only=True))
    assert survives["total"] == 1, survives
