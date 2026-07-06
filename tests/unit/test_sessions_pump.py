from pare_frida_mcp.config import Config
from pare_frida_mcp.core.sessions import SessionManager


class FakeScript:
    def __init__(self):
        self._cb = None
    def on(self, event, cb):
        self._cb = cb
    def emit(self, message):
        self._cb(message, None)


def _cfg(tmp_path):
    return Config(capture_dir=tmp_path, max_tool_bytes=4096,
                  blob_threshold=65536, max_disk_per_session=10**9)


def _hook_evt(seq, method="encryptString"):
    return {"type": "send", "payload": {
        "hook": True, "seq": seq, "class": "C", "method": method,
        "overload": ["[B"], "args": [{"utf8": "hi", "hex": "6869"}],
        "ret": None, "threw": False, "thread": 1}}


def test_hook_events_are_retained(tmp_path):
    mgr = SessionManager(_cfg(tmp_path))
    script = FakeScript()
    sid = mgr.register_session(script=script, pid=1, name="x")
    script.emit(_hook_evt(1))
    script.emit(_hook_evt(2))
    assert [e["seq"] for e in mgr.get(sid)._events] == [1, 2]
    mgr.close_all()


def test_non_hook_messages_are_segregated(tmp_path):
    mgr = SessionManager(_cfg(tmp_path))
    script = FakeScript()
    sid = mgr.register_session(script=script, pid=1, name="x")
    script.emit({"type": "send", "payload": {"noise": 1}})   # non-hook send
    script.emit({"type": "error", "description": "boom"})      # frida error
    s = mgr.get(sid)
    assert list(s._events) == []
    assert len(s._diagnostics) == 2
    mgr.close_all()


def test_ring_buffer_evicts_oldest(tmp_path):
    mgr = SessionManager(_cfg(tmp_path), event_bound=3)
    script = FakeScript()
    sid = mgr.register_session(script=script, pid=1, name="x")
    for n in range(1, 6):
        script.emit(_hook_evt(n))
    assert [e["seq"] for e in mgr.get(sid)._events] == [3, 4, 5]
    mgr.close_all()
