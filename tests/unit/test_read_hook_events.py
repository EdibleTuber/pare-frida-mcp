import json
import pytest

from pare_frida_mcp import tools as T
from pare_frida_mcp.core.sessions import SessionManager


class _FakeScript:
    def on(self, *a, **k): pass


class _FakeFrida:
    def __init__(self, detached=False): self.is_detached = detached


def _live_session_with_events(n):
    sid = T.MANAGER.register_session(script=_FakeScript(), pid=1, name="x")
    T.MANAGER.get(sid).frida_session = _FakeFrida(False)
    for seq in range(1, n + 1):
        T.MANAGER.get(sid)._events.append(
            {"seq": seq, "class": "C", "method": "m", "args": [], "ret": None})
    return sid


@pytest.mark.asyncio
async def test_reads_events_via_active_session():
    _live_session_with_events(3)
    res = json.loads(await T.read_hook_events())   # no session_id, since_seq=0
    assert res.get("error") is not True
    assert [e["seq"] for e in res["events"]] == [1, 2, 3]
    assert res["has_more"] is False and res["next_seq"] == 3 and res["lost"] == 0


@pytest.mark.asyncio
async def test_has_more_summary_directs_next_cursor():
    sid = _live_session_with_events(5)
    res = json.loads(await T.read_hook_events(since_seq=0, limit=2, session_id=sid))
    assert res["has_more"] is True and res["next_seq"] == 2
    assert "since_seq=2" in res["summary"]


@pytest.mark.asyncio
async def test_limit_is_clamped():
    sid = _live_session_with_events(3)
    res = json.loads(await T.read_hook_events(limit=10**9, session_id=sid))
    assert res.get("error") is not True and len(res["events"]) == 3


@pytest.mark.asyncio
async def test_no_live_session_errors_with_attach_hint():
    res = json.loads(await T.read_hook_events())
    assert res["error"] is True and "attach" in json.dumps(res).lower()
