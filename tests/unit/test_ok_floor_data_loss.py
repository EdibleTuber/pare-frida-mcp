"""Regressions for the _ok valid-JSON floor dropping ALL data on overflow.

The floor (Task: _ok/_err never emit invalid JSON) returns a generic fallback
envelope when a payload exceeds _CAP. Several call paths fed it oversized
content and so silently lost all structured data. These tests pin the fixes.
"""
import json
import pytest

from pare_frida_mcp import tools as T
from pare_frida_mcp.core import memory as memory_mod
from pare_frida_mcp.core import scripts as scripts_mod
from pare_frida_mcp.capture.store import CaptureStore
from pare_frida_mcp.core.snapshots import SNAPSHOT_HANDLE
from pare_frida_mcp.ids import new_session_id


class _DummySession:
    def __init__(self):
        self.script = object()
        self.frida_session = object()
        self.store = CaptureStore.open_memory()


# --- Fix 1: enumerate_exports must return a bounded list, not empty fallback ---

@pytest.mark.asyncio
async def test_enumerate_exports_returns_bounded_list_not_empty_fallback(monkeypatch):
    sid = new_session_id()
    T.MANAGER._sessions[sid] = _DummySession()
    monkeypatch.setattr(memory_mod, "enumerate_exports",
                        lambda script, module: [{"name": "e" * 60, "address": hex(i)} for i in range(300)])
    try:
        res = json.loads(await T.enumerate_exports(sid, module="libc.so"))
        assert "exports" in res, res
        assert 0 < len(res["exports"]) < 300
        assert res["total"] == 300
    finally:
        T.MANAGER._sessions.pop(sid, None)


# --- Fix 2: byte_budget above the cap must clamp, not empty the result ---

@pytest.mark.asyncio
async def test_search_byte_budget_above_cap_is_clamped_not_emptied():
    T.SNAPSHOTS.replace("big", [{"pid": i, "name": "x" * 100} for i in range(60)])
    res = json.loads(await T.search_capture(SNAPSHOT_HANDLE, field="source",
                                            contains="big", byte_budget=100000))
    assert "matches" in res, res                 # NOT the empty fallback
    assert res["matches"]                          # non-empty
    assert len(res["matches"]) < 60                # still bounded to the cap


@pytest.mark.asyncio
async def test_read_capture_byte_budget_above_cap_is_clamped_not_emptied():
    seq = T.SNAPSHOTS.store.write({"type": "snapshot", "source": "r",
                                   "summary": "s", "payload": {"data": "Q" * 10000}})
    res = json.loads(await T.read_capture(SNAPSHOT_HANDLE, seq=seq, byte_budget=100000))
    assert "text" in res, res                      # NOT the empty fallback
    assert len(res["text"].encode("utf-8")) <= T._CAP


# --- Fix 3: execute_script must not lose results at the inline/spill boundary ---

@pytest.mark.asyncio
async def test_execute_script_spills_at_envelope_boundary_no_data_loss(monkeypatch):
    sid = new_session_id()
    T.MANAGER._sessions[sid] = _DummySession()
    # Sized so {"value": big} fits _CAP but the _ok envelope (adds a summary key)
    # does not — the old probe under-measured and lost the result.
    big = "Q" * (T._CAP - 20)
    monkeypatch.setattr(scripts_mod, "execute_ad_hoc", lambda fs, src: big)
    try:
        res = json.loads(await T.execute_script(sid, "whatever"))
        assert res.get("error") is not True, res   # must NOT be the lossy fallback
        assert ("result" in res) or ("capture" in res), res  # inline or spilled, never lost
    finally:
        T.MANAGER._sessions.pop(sid, None)
