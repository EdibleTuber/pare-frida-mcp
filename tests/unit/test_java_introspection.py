import json

import pytest

from pare_frida_mcp import tools as T
from pare_frida_mcp.android import java as java_mod
from pare_frida_mcp.contract import TOOL_SPECS
from pare_frida_mcp.ids import new_session_id


class _DummySession:
    """Minimal stand-in for a live Session (mirrors test_tools_enum)."""
    def __init__(self):
        self.script = object()
        self.frida_session = None

    def flush(self):
        pass


def _by_name():
    return {s.name: s for s in TOOL_SPECS}


@pytest.mark.asyncio
async def test_enumerate_classes_returns_envelope(monkeypatch):
    sid = new_session_id()
    T.MANAGER._sessions[sid] = _DummySession()
    classes = ["a.B", "a.C", "a.D"]
    monkeypatch.setattr(java_mod, "enumerate_classes", lambda script, filter: classes)
    try:
        doc = json.loads(await T.enumerate_classes(filter="a", session_id=sid))
        assert doc.get("error") is not True, doc
        assert doc["classes"] == classes
        assert doc["summary"] == "3 classes"
    finally:
        T.MANAGER._sessions.pop(sid, None)


@pytest.mark.asyncio
async def test_enumerate_classes_no_live_session_errors():
    res = json.loads(await T.enumerate_classes(filter="", session_id=new_session_id()))
    assert res.get("error") is True


def test_enumerate_classes_is_low_tier():
    assert _by_name()["enumerate_classes"].risk_tier == "low"


@pytest.mark.asyncio
async def test_enumerate_methods_returns_envelope(monkeypatch):
    sid = new_session_id()
    T.MANAGER._sessions[sid] = _DummySession()
    methods = [
        {"name": "encryptString", "signature": "public void C.encryptString(java.lang.String)"},
        {"name": "decryptString", "signature": "public void C.decryptString(java.lang.String)"},
    ]
    monkeypatch.setattr(java_mod, "enumerate_methods", lambda script, cls: methods)
    try:
        doc = json.loads(await T.enumerate_methods(cls="a.C", session_id=sid))
        assert doc.get("error") is not True, doc
        assert doc["methods"] == methods
        assert doc["summary"] == "2 methods for a.C"
    finally:
        T.MANAGER._sessions.pop(sid, None)


@pytest.mark.asyncio
async def test_enumerate_methods_no_live_session_errors():
    res = json.loads(await T.enumerate_methods(cls="a.C", session_id=new_session_id()))
    assert res.get("error") is True


def test_enumerate_methods_is_low_tier():
    assert _by_name()["enumerate_methods"].risk_tier == "low"
