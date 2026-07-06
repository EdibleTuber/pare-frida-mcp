"""Active-session resolution: session-scoped tools default an omitted session_id
to the most-recent LIVE session, so the operator/model doesn't have to restate
the session id it just got from attach. Also covers the enumerate_classes 500-cap
truncation signal."""
import json

import pytest

from pare_frida_mcp import tools as T
from pare_frida_mcp.core.sessions import SessionManager


class _FakeExports:
    def __init__(self, modules=None, classes=None):
        self._modules = modules if modules is not None else [{"name": "libc.so"}]
        self._classes = classes if classes is not None else []

    def modules(self, filter=""):
        return self._modules

    def java_enumerate(self, filter=""):
        return self._classes


class _FakeScript:
    def __init__(self, exports=None):
        self.exports_sync = exports or _FakeExports()

    def on(self, *a, **k):
        pass


class _FakeFrida:
    def __init__(self, detached=False):
        self.is_detached = detached


def _register(mgr, pid, name, *, detached, exports=None):
    sid = mgr.register_session(script=_FakeScript(exports), pid=pid, name=name)
    mgr.get(sid).frida_session = _FakeFrida(detached)
    return sid


def test_active_session_none_when_empty():
    assert SessionManager(T.CFG).active_session() is None


def test_active_session_returns_most_recent_live():
    mgr = SessionManager(T.CFG)
    _register(mgr, 1, "a", detached=False)
    b = _register(mgr, 2, "b", detached=False)
    assert mgr.active_session() == b


def test_active_session_skips_dead_most_recent():
    mgr = SessionManager(T.CFG)
    a = _register(mgr, 1, "a", detached=False)
    _register(mgr, 2, "b", detached=True)  # most recent but dead
    assert mgr.active_session() == a


@pytest.mark.asyncio
async def test_tool_defaults_to_active_session():
    _register(T.MANAGER, 1, "a", detached=False)
    res = json.loads(await T.enumerate_modules())  # no session_id passed
    assert res.get("error") is not True
    assert res["modules"] == [{"name": "libc.so"}]


@pytest.mark.asyncio
async def test_tool_errors_clearly_when_no_live_session():
    res = json.loads(await T.enumerate_modules())  # empty manager
    assert res["error"] is True
    assert "attach" in json.dumps(res).lower()


@pytest.mark.asyncio
async def test_explicit_session_id_still_honored():
    sid = _register(T.MANAGER, 7, "x", detached=False)
    res = json.loads(await T.enumerate_modules(session_id=sid))
    assert res.get("error") is not True


@pytest.mark.asyncio
async def test_enumerate_classes_flags_cap():
    sid = _register(T.MANAGER, 1, "a", detached=False,
                    exports=_FakeExports(classes=["c"] * 500))
    res = json.loads(await T.enumerate_classes(session_id=sid))
    assert "cap" in res["summary"].lower()


@pytest.mark.asyncio
async def test_enumerate_classes_no_cap_note_under_limit():
    sid = _register(T.MANAGER, 1, "a", detached=False,
                    exports=_FakeExports(classes=["c", "c", "c"]))
    res = json.loads(await T.enumerate_classes(session_id=sid))
    assert "cap" not in res["summary"].lower()
