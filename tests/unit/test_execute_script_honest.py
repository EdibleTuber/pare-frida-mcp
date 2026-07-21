"""execute_ad_hoc / execute_script surface an honest record of what a script did.

Root cause this locks in (confirmed live on Frida 17): a bare ad-hoc script has
no Java bridge, so `Java.perform` throws `ReferenceError: 'Java' is not defined`.
The old code inspected only `type=="send"`, swallowed the error, and returned
None -> the model misread it as a timeout. It also dropped console.log and kept
only the LAST send. option B returns {"sends":[...], "logs":[...], "error":...}.
"""
import json

import pytest

from pare_frida_mcp import tools as T
from pare_frida_mcp.core import scripts as scripts_mod
from pare_frida_mcp.ids import new_session_id


class FakeAdHocScript:
    """Simulates a Frida Script: on load() it replays scripted messages to the
    on('message') callback and scripted lines to the log handler."""

    def __init__(self, messages=(), logs=()):
        self._messages = list(messages)
        self._logs = list(logs)
        self._on = None
        self._log_handler = None
        self.unloaded = False

    def on(self, event, cb):
        if event == "message":
            self._on = cb

    def set_log_handler(self, cb):
        self._log_handler = cb

    def load(self):
        for m in self._messages:
            self._on(m, None)
        for level, text in self._logs:
            if self._log_handler is not None:
                self._log_handler(level, text)

    def unload(self):
        self.unloaded = True


class FakeSession:
    def __init__(self, script):
        self._script = script

    def create_script(self, source):
        return self._script


# --- core: execute_ad_hoc -----------------------------------------------------

def test_java_undefined_error_is_surfaced_not_swallowed():
    script = FakeAdHocScript(messages=[
        {"type": "error", "description": "ReferenceError: 'Java' is not defined",
         "stack": "ReferenceError: 'Java' is not defined\n    at <eval> (/script1.js:1)"},
    ])
    res = scripts_mod.execute_ad_hoc(FakeSession(script), "Java.perform(function(){})")
    assert res["error"] and "Java" in res["error"]      # not None, not swallowed
    assert res["sends"] == []
    assert script.unloaded is True


def test_console_log_is_captured():
    script = FakeAdHocScript(logs=[("info", "hello from script")])
    res = scripts_mod.execute_ad_hoc(FakeSession(script), "console.log('hello from script')")
    assert res["logs"] == ["hello from script"]
    assert res["error"] is None


def test_all_sends_collected_not_just_last():
    script = FakeAdHocScript(messages=[
        {"type": "send", "payload": "a"},
        {"type": "send", "payload": "b"},
    ])
    res = scripts_mod.execute_ad_hoc(FakeSession(script), "send('a'); send('b')")
    assert res["sends"] == ["a", "b"]                    # both, not just 'b'
    assert res["error"] is None


def test_plain_send_roundtrips():
    script = FakeAdHocScript(messages=[{"type": "send", "payload": 1}])
    res = scripts_mod.execute_ad_hoc(FakeSession(script), "send(1)")
    assert res["sends"] == [1]
    assert res["logs"] == []
    assert res["error"] is None


# --- tool: execute_script wrapper --------------------------------------------

class _DummySession:
    def __init__(self):
        self.frida_session = object()

    def flush(self):
        pass


@pytest.mark.asyncio
async def test_execute_script_tool_surfaces_error_in_summary(monkeypatch):
    sid = new_session_id()
    T.MANAGER._sessions[sid] = _DummySession()
    monkeypatch.setattr(scripts_mod, "execute_ad_hoc", lambda fsess, src: {
        "sends": [], "logs": [], "error": "ReferenceError: 'Java' is not defined"})
    try:
        doc = json.loads(await T.execute_script(source="Java.perform(()=>{})", session_id=sid))
        assert "Java" in doc["summary"]                 # error is visible, not a silent null
        assert doc["error"] == "ReferenceError: 'Java' is not defined"
        assert "result" not in doc                       # old scalar key gone
    finally:
        T.MANAGER._sessions.pop(sid, None)


@pytest.mark.asyncio
async def test_execute_script_tool_success_lists_sends_and_logs(monkeypatch):
    sid = new_session_id()
    T.MANAGER._sessions[sid] = _DummySession()
    monkeypatch.setattr(scripts_mod, "execute_ad_hoc", lambda fsess, src: {
        "sends": [{"classes": ["A", "B"]}], "logs": ["trace"], "error": None})
    try:
        doc = json.loads(await T.execute_script(source="send({classes:['A','B']})", session_id=sid))
        assert doc.get("error") in (None, False) or doc["error"] is None
        assert doc["summary"].startswith("eval complete")
        assert doc["sends"] == [{"classes": ["A", "B"]}]
        assert doc["logs"] == ["trace"]
        assert "result" not in doc
        assert "capture" not in doc
    finally:
        T.MANAGER._sessions.pop(sid, None)


# --- completion-value capture (execute_script return-value gap) ---------------

def test_source_is_wrapped_to_capture_completion_value():
    """The source is wrapped so its completion value (e.g. the return of a trailing
    solve()) is auto-captured via indirect eval + a marked send — the model does not
    have to remember to send() it."""
    captured = {}

    class CapSession:
        def create_script(self, source):
            captured["source"] = source
            return FakeAdHocScript()

    scripts_mod.execute_ad_hoc(CapSession(), "solve()")
    src = captured["source"]
    assert "__adhoc_result__" in src          # the result marker is injected
    assert "(0,eval)" in src                    # completion value via indirect eval
    assert json.dumps("solve()") in src         # original source embedded as a JS string


def test_completion_value_captured_as_value_not_a_user_send():
    script = FakeAdHocScript(messages=[
        {"type": "send", "payload": {"__adhoc_result__": True, "value": "SuperSecret"}},
    ])
    res = scripts_mod.execute_ad_hoc(FakeSession(script), "solve()")
    assert res["value"] == "SuperSecret"
    assert res["sends"] == []                    # the marked result is NOT a user send
    assert res["error"] is None


def test_user_sends_and_completion_value_coexist():
    script = FakeAdHocScript(messages=[
        {"type": "send", "payload": "user1"},
        {"type": "send", "payload": {"__adhoc_result__": True, "value": 42}},
    ])
    res = scripts_mod.execute_ad_hoc(FakeSession(script), "send('user1'); 42")
    assert res["sends"] == ["user1"]
    assert res["value"] == 42


def test_value_is_none_when_no_completion_marker():
    script = FakeAdHocScript(messages=[{"type": "send", "payload": "x"}])
    res = scripts_mod.execute_ad_hoc(FakeSession(script), "send('x')")
    assert res.get("value") is None
    assert res["sends"] == ["x"]


@pytest.mark.asyncio
async def test_execute_script_tool_surfaces_value(monkeypatch):
    sid = new_session_id()
    T.MANAGER._sessions[sid] = _DummySession()
    monkeypatch.setattr(scripts_mod, "execute_ad_hoc", lambda fsess, src: {
        "sends": [], "logs": [], "error": None, "value": "SuperSecret"})
    try:
        doc = json.loads(await T.execute_script(source="solve()", session_id=sid))
        assert doc["value"] == "SuperSecret"
        assert "SuperSecret" in doc["summary"]   # visible in the summary, not just a field
    finally:
        T.MANAGER._sessions.pop(sid, None)
