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
