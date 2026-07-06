from pare_frida_mcp.config import Config
from pare_frida_mcp.core.sessions import SessionManager


class FakeScript:
    def on(self, event, cb): self._cb = cb


def _mgr(tmp_path, event_bound=2048):
    cfg = Config(capture_dir=tmp_path, max_tool_bytes=4096,
                 blob_threshold=65536, max_disk_per_session=10**9)
    return SessionManager(cfg, event_bound=event_bound)


def _fill(mgr, n, event_bound=2048):
    sid = mgr.register_session(script=FakeScript(), pid=1, name="x")
    for seq in range(1, n + 1):
        mgr.get(sid)._events.append({"seq": seq, "class": "C", "method": "m"})
    return sid


def test_since_seq_selects_newer_events(tmp_path):
    mgr = _mgr(tmp_path); sid = _fill(mgr, 5)
    r = mgr.read_events(sid, since_seq=2, limit=100, max_bytes=10**6)
    assert [e["seq"] for e in r.events] == [3, 4, 5]
    assert r.next_seq == 5 and r.buffered_remaining == 0 and r.has_more is False
    assert r.lost == 0


def test_limit_paginates_and_reports_more(tmp_path):
    mgr = _mgr(tmp_path); sid = _fill(mgr, 5)
    r = mgr.read_events(sid, since_seq=0, limit=2, max_bytes=10**6)
    assert [e["seq"] for e in r.events] == [1, 2]
    assert r.next_seq == 2 and r.buffered_remaining == 3 and r.has_more is True
    assert r.lost == 0


def test_max_bytes_bounds_but_always_returns_one(tmp_path):
    mgr = _mgr(tmp_path); sid = _fill(mgr, 5)
    r = mgr.read_events(sid, since_seq=0, limit=100, max_bytes=1)
    assert len(r.events) == 1 and r.has_more is True


def test_lost_reported_when_cursor_fell_behind_eviction(tmp_path):
    # ring holds only the last 3 (seq 3,4,5); a cursor at 0 missed seq 1,2
    mgr = _mgr(tmp_path, event_bound=3); sid = _fill(mgr, 5, event_bound=3)
    r = mgr.read_events(sid, since_seq=0, limit=100, max_bytes=10**6)
    assert [e["seq"] for e in r.events] == [3, 4, 5]
    assert r.lost == 2   # seq 1 and 2 evicted before the cursor could read them


def test_caught_up_cursor_returns_empty_no_loss(tmp_path):
    mgr = _mgr(tmp_path); sid = _fill(mgr, 3)
    r = mgr.read_events(sid, since_seq=3, limit=100, max_bytes=10**6)
    assert r.events == [] and r.next_seq == 3 and r.has_more is False and r.lost == 0
