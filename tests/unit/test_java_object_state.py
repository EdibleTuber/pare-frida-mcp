import json
import pytest

from pare_frida_mcp import tools as T
from pare_frida_mcp.android import java as java_mod
from pare_frida_mcp.ids import new_session_id


class _DummySession:
    """Minimal stand-in for a live Session (mirrors test_java_introspection)."""
    def __init__(self):
        self.script = object()
        self.frida_session = None
    def flush(self):
        pass


def _sid():
    sid = new_session_id()
    T.MANAGER._sessions[sid] = _DummySession()
    return sid


@pytest.mark.asyncio
async def test_read_fields_instance_envelope(monkeypatch):
    sid = _sid()
    canned = {"cls": "a.C", "instance_count": 1,
              "instances": [{"fields": {"plainText": "s3cr3t"}}],
              "static_fields": {}, "capped": False}
    monkeypatch.setattr(java_mod, "java_read_fields", lambda script, cls, fields: canned)
    try:
        doc = json.loads(await T.java_read_fields(cls="a.C", fields=["plainText"], session_id=sid))
        assert doc.get("error") is not True, doc
        assert doc["instances"] == [{"fields": {"plainText": "s3cr3t"}}]
        assert doc["instance_count"] == 1
        assert 'plainText="s3cr3t"' in doc["summary"]   # value folded inline
        assert doc["capped"] is False
    finally:
        T.MANAGER._sessions.pop(sid, None)


@pytest.mark.asyncio
async def test_read_fields_empty_gives_guidance(monkeypatch):
    sid = _sid()
    canned = {"cls": "a.C", "instance_count": 0, "instances": [],
              "static_fields": {}, "capped": False}
    monkeypatch.setattr(java_mod, "java_read_fields", lambda script, cls, fields: canned)
    try:
        doc = json.loads(await T.java_read_fields(cls="a.C", session_id=sid))
        assert doc.get("error") is not True, doc
        assert "trigger" in doc["summary"] and "capture_this" in doc["summary"]
    finally:
        T.MANAGER._sessions.pop(sid, None)


@pytest.mark.asyncio
async def test_read_fields_static_only(monkeypatch):
    sid = _sid()
    canned = {"cls": "a.C", "instance_count": 0, "instances": [],
              "static_fields": {"SECRET": "abc"}, "capped": False}
    monkeypatch.setattr(java_mod, "java_read_fields", lambda script, cls, fields: canned)
    try:
        doc = json.loads(await T.java_read_fields(cls="a.C", fields=["SECRET"], session_id=sid))
        assert doc.get("error") is not True, doc
        assert doc["static_fields"] == {"SECRET": "abc"}
        assert "static field" in doc["summary"]
    finally:
        T.MANAGER._sessions.pop(sid, None)


@pytest.mark.asyncio
async def test_read_fields_no_live_session_errors():
    res = json.loads(await T.java_read_fields(cls="a.C", session_id=new_session_id()))
    assert res.get("error") is True


@pytest.mark.asyncio
async def test_capture_this_forwarded(monkeypatch):
    calls = {}
    def fake(script, cls, method, overload=None, capture_this=None):
        calls["args"] = (cls, method, overload, capture_this)
        return {"hook": f"{cls}.{method}", "since_seq": 3}
    sid = _sid()
    monkeypatch.setattr(java_mod, "java_hook", fake)
    try:
        res = json.loads(await T.java_hook(cls="a.C", method="decryptString",
                                           capture_this=["plainText"], session_id=sid))
        assert res.get("error") is not True, res
        assert calls["args"] == ("a.C", "decryptString", None, ["plainText"])
    finally:
        T.MANAGER._sessions.pop(sid, None)
