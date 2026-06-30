"""Unbounded tool results spill their FULL payload to a capture store instead of
truncating; the model retrieves the complete result via read_capture. Bounded
small status/control values still ride inline so chaining needs no round-trip."""
import json
import pytest

from pare_frida_mcp import tools as T
from pare_frida_mcp.core import memory as memory_mod
from pare_frida_mcp.capture.store import CaptureStore
from pare_frida_mcp.ids import new_session_id


class _DummySession:
    def __init__(self):
        self.script = object()
        self.frida_session = object()
        self.store = CaptureStore.open_memory()

    def flush(self):
        pass


@pytest.mark.asyncio
async def test_read_memory_spills_full_region_no_truncation(monkeypatch):
    sid = new_session_id()
    T.MANAGER._sessions[sid] = _DummySession()
    # 256 bytes -> 512 hex chars, 4x the 64-byte (128 hex char) preview. The old
    # handler returned only the preview and silently dropped the rest.
    data = bytes(range(256))
    monkeypatch.setattr(memory_mod, "read_memory", lambda script, addr, size: data)
    try:
        res = json.loads(await T.read_memory(sid, "0x1000", len(data)))
        assert res.get("error") is not True, res
        # Full region spilled to a capture handle, not truncated to a preview.
        assert "capture" in res, res
        seq = res["capture"]["seq"]
        full = json.loads(await T.read_capture(sid, seq=seq, byte_budget=100000))
        # The COMPLETE hex is retrievable — nothing past the preview is lost.
        assert data.hex() in full["text"], full
    finally:
        T.MANAGER._sessions.pop(sid, None)


@pytest.mark.asyncio
async def test_read_memory_small_region_visible_inline(monkeypatch):
    """A small read is fully visible via the inline preview — no round-trip
    needed for the common case."""
    sid = new_session_id()
    T.MANAGER._sessions[sid] = _DummySession()
    data = bytes(range(16))  # 16 bytes <= 64-byte preview window
    monkeypatch.setattr(memory_mod, "read_memory", lambda script, addr, size: data)
    try:
        res = json.loads(await T.read_memory(sid, "0x10", 16))
        assert res["hex_preview"] == data.hex()  # whole region readable inline
    finally:
        T.MANAGER._sessions.pop(sid, None)
