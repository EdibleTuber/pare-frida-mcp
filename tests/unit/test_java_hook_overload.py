import json
import pytest

from pare_frida_mcp import tools as T


class _Exports:
    def __init__(self, result):
        self._result = result
        self.calls = []
    def java_hook_install(self, cls, method, overload):
        self.calls.append((cls, method, overload))
        return self._result


class _FakeScript:
    def __init__(self, result): self.exports_sync = _Exports(result)
    def on(self, *a, **k): pass


class _FakeFrida:
    def __init__(self): self.is_detached = False


def _session(result):
    sid = T.MANAGER.register_session(script=_FakeScript(result), pid=1, name="x")
    T.MANAGER.get(sid).frida_session = _FakeFrida()
    return sid


@pytest.mark.asyncio
async def test_overload_list_passed_through():
    sid = _session({"hook": "C.write", "since_seq": 7})
    res = json.loads(await T.java_hook(cls="C", method="write",
                                       overload=["[B", "int", "int"], session_id=sid))
    assert res.get("error") is not True
    assert res["hook"]["since_seq"] == 7
    assert T.MANAGER.get(sid).script.exports_sync.calls == [("C", "write", ["[B", "int", "int"])]


@pytest.mark.asyncio
async def test_ambiguous_overload_returns_choices():
    sid = _session({"ambiguous": True, "overloads": [["[B"], ["[B", "int", "int"]]})
    res = json.loads(await T.java_hook(cls="C", method="write", session_id=sid))
    assert res["error"] is True
    assert res["overloads"] == [["[B"], ["[B", "int", "int"]]
    assert "overload" in res["summary"].lower()
