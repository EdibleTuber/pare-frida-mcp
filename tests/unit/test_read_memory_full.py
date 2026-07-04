"""read_memory and execute_script return full results inline; no seq-handle spill."""
import json
import pytest

from pare_frida_mcp import tools as T
from pare_frida_mcp.core import memory as memory_mod
from pare_frida_mcp.core import scripts as scripts_mod
from pare_frida_mcp.ids import new_session_id


class _DummySession:
    def __init__(self):
        self.script = object()
        self.frida_session = object()

    def flush(self):
        pass


@pytest.mark.asyncio
async def test_read_memory_returns_full_hex_no_handle(monkeypatch):
    sid = new_session_id()
    T.MANAGER._sessions[sid] = _DummySession()
    data = bytes(range(256)) * 40  # 10 240 bytes
    monkeypatch.setattr(memory_mod, "read_memory", lambda script, addr, size: data)
    try:
        out = await T.read_memory(sid, "0x401000", len(data))
        doc = json.loads(out)
        assert doc.get("error") is not True, doc
        assert doc["address"] == "0x401000"
        assert doc["bytes"] == 10240
        assert len(bytes.fromhex(doc["hex"])) == 10240   # full region, not a 64-byte preview
        assert "capture" not in doc                       # no seq-handle
        assert "hex_preview" not in doc                   # old field removed
    finally:
        T.MANAGER._sessions.pop(sid, None)


@pytest.mark.asyncio
async def test_read_memory_small_region_full_hex_inline(monkeypatch):
    """Even small reads use the new shape: full hex in the 'hex' field."""
    sid = new_session_id()
    T.MANAGER._sessions[sid] = _DummySession()
    data = bytes(range(16))
    monkeypatch.setattr(memory_mod, "read_memory", lambda script, addr, size: data)
    try:
        doc = json.loads(await T.read_memory(sid, "0x10", 16))
        assert doc["hex"] == data.hex()
        assert "capture" not in doc
        assert "hex_preview" not in doc
    finally:
        T.MANAGER._sessions.pop(sid, None)


@pytest.mark.asyncio
async def test_execute_script_returns_result_inline(monkeypatch):
    """execute_script returns {"summary": "eval complete", "result": ...} with no spill."""
    sid = new_session_id()
    T.MANAGER._sessions[sid] = _DummySession()
    large_value = "x" * 10000  # larger than old _CAP, now returns inline
    monkeypatch.setattr(scripts_mod, "execute_ad_hoc", lambda fsess, src: large_value)
    try:
        doc = json.loads(await T.execute_script(sid, "1+1"))
        assert doc.get("error") is not True, doc
        assert doc["summary"] == "eval complete"
        assert doc["result"] == large_value
        assert "capture" not in doc
    finally:
        T.MANAGER._sessions.pop(sid, None)
