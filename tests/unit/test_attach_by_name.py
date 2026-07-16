"""attach(target=<name>) must resolve an Android *application* by its package
identifier, not only by exact process name.

Regression for the OMTG run: the model attached with
``target='sg.vp.owasp_mobile.omtg_android'`` (the package). That string is the
application's ``identifier``; the running process's ``name`` is the app label
("Attack me if u can"), so the old exact ``p.name == target`` match found
nothing and the model was forced to fall back to attach-by-pid.
"""
import json

import pytest

from pare_frida_mcp import tools as T
from pare_frida_mcp.core import devices as devices_mod
from pare_frida_mcp.core import scripts as scripts_mod


class _FakeScript:
    def on(self, event, cb):
        pass


class _FakeFridaSession:
    def __init__(self, detached=False):
        self.is_detached = detached


class _Proc:
    def __init__(self, pid, name):
        self.pid = pid
        self.name = name


class _App:
    def __init__(self, identifier, name, pid):
        self.identifier = identifier
        self.name = name
        self.pid = pid


class _FakeDevice:
    def __init__(self, dev_id="emulator-5554", procs=None, apps=None):
        self.id = dev_id
        self.attach_calls = []
        self._procs = procs or []
        self._apps = apps or []

    def attach(self, pid):
        self.attach_calls.append(pid)
        return _FakeFridaSession(detached=False)

    def enumerate_processes(self):
        return self._procs

    def enumerate_applications(self, scope=None):
        return self._apps


@pytest.fixture(autouse=True)
def _stub_script(monkeypatch):
    monkeypatch.setattr(scripts_mod, "load_bundled_script", lambda fs: _FakeScript())


def _install(monkeypatch, dev):
    monkeypatch.setattr(devices_mod, "get_device", lambda _id: dev)


def _cleanup(sid):
    if sid:
        T.MANAGER._sessions.pop(sid, None)


PKG = "sg.vp.owasp_mobile.omtg_android"


@pytest.mark.asyncio
async def test_attach_by_package_identifier_resolves_via_applications(monkeypatch):
    # No process is named after the package; the running app carries the label
    # as its process name but the package as its application identifier.
    dev = _FakeDevice(
        procs=[_Proc(19322, "Attack me if u can"), _Proc(1, "zygote64")],
        apps=[_App(PKG, "Attack me if u can", 19322)],
    )
    _install(monkeypatch, dev)
    sid = None
    try:
        doc = json.loads(await T.attach(PKG))
        assert doc.get("error") is not True, doc
        assert doc["pid"] == 19322
        assert dev.attach_calls == [19322]
        sid = doc["session_id"]
    finally:
        _cleanup(sid)


@pytest.mark.asyncio
async def test_attach_by_process_name_still_works(monkeypatch):
    dev = _FakeDevice(procs=[_Proc(4242, "system_server")], apps=[])
    _install(monkeypatch, dev)
    sid = None
    try:
        doc = json.loads(await T.attach("system_server"))
        assert doc.get("error") is not True, doc
        assert doc["pid"] == 4242
        assert dev.attach_calls == [4242]
        sid = doc["session_id"]
    finally:
        _cleanup(sid)


@pytest.mark.asyncio
async def test_installed_but_not_running_app_is_not_found(monkeypatch):
    # identifier matches an app, but it has no live pid -> cannot attach.
    dev = _FakeDevice(procs=[_Proc(1, "zygote64")],
                      apps=[_App(PKG, "Attack me if u can", 0)])
    _install(monkeypatch, dev)
    doc = json.loads(await T.attach(PKG))
    assert doc["error"] is True
    assert PKG in json.dumps(doc)


@pytest.mark.asyncio
async def test_unknown_target_errors(monkeypatch):
    dev = _FakeDevice(procs=[_Proc(1, "zygote64")], apps=[_App("com.other", "Other", 55)])
    _install(monkeypatch, dev)
    doc = json.loads(await T.attach("com.nope"))
    assert doc["error"] is True
