from pare_frida_mcp.config import Config
from pare_frida_mcp.core.sessions import SessionManager

class FakeScript:
    def __init__(self):
        self._cb = None
    def on(self, event, cb):
        self._cb = cb
    def emit(self, message):           # test helper to simulate Frida send()
        self._cb(message, None)

def test_session_receives_and_flushes_messages(tmp_path):
    cfg = Config(capture_dir=tmp_path, max_tool_bytes=4096,
                 blob_threshold=65536, max_disk_per_session=10**9)
    mgr = SessionManager(cfg)
    script = FakeScript()
    sid = mgr.register_session(script=script, pid=123, name="com.x")
    script.emit({"type": "send", "payload": {"method": "doLogin"}})
    mgr.flush(sid)  # drains queue without error
    mgr.close_all()

def test_drops_past_queue_bound_with_counter(tmp_path):
    cfg = Config(capture_dir=tmp_path, max_tool_bytes=4096,
                 blob_threshold=65536, max_disk_per_session=10**9)
    mgr = SessionManager(cfg, queue_bound=2)
    script = FakeScript()
    sid = mgr.register_session(script=script, pid=1, name="x")
    for _ in range(5):
        script.emit({"type": "send", "payload": {}})
    assert mgr.dropped_count(sid) == 3
    mgr.close_all()
