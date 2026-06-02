import json
import pytest

from pare_frida_mcp import tools as T
from pare_frida_mcp.core import devices as devices_mod
from pare_frida_mcp.core.snapshots import SNAPSHOT_HANDLE


class FakeProc:
    def __init__(self, pid, name):
        self.pid, self.name = pid, name


class FakeApp:
    def __init__(self, identifier, name, pid):
        self.identifier, self.name, self.pid = identifier, name, pid


class FakeDevice:
    def __init__(self, type="usb", id="emulator-5554", procs=(), apps=()):
        self.type, self.id = type, id
        self._procs, self._apps = list(procs), list(apps)

    def enumerate_processes(self):
        return self._procs

    def enumerate_applications(self, scope=None):
        return self._apps


@pytest.mark.asyncio
async def test_enumerate_processes_persists_and_returns_handle(monkeypatch):
    dev = FakeDevice(procs=[FakeProc(1, "zygote"), FakeProc(2, "system_server")])
    monkeypatch.setattr(devices_mod, "get_device", lambda _id: dev)
    res = json.loads(await T.enumerate_processes(device_id="emulator-5554"))
    assert res["store"] == SNAPSHOT_HANDLE
    assert res["total"] == 2
    assert res["source"] == "enumerate_processes:device=emulator-5554"
    assert res.get("error") is not True
    found = json.loads(await T.search_capture(SNAPSHOT_HANDLE, field="source",
                                              contains=res["source"]))
    assert found["total"] == 2


@pytest.mark.asyncio
async def test_enumerate_processes_replace_semantics(monkeypatch):
    dev = FakeDevice(procs=[FakeProc(1, "old_a"), FakeProc(2, "old_b")])
    monkeypatch.setattr(devices_mod, "get_device", lambda _id: dev)
    await T.enumerate_processes(device_id="emulator-5554")
    dev._procs = [FakeProc(9, "fresh_only")]
    res = json.loads(await T.enumerate_processes(device_id="emulator-5554"))
    found = json.loads(await T.search_capture(SNAPSHOT_HANDLE, field="source",
                                              contains=res["source"]))
    names = {m["summary"] for m in found["matches"]}
    assert names == {"fresh_only"}


@pytest.mark.asyncio
async def test_enumerate_key_normalizes_on_resolved_device_id(monkeypatch):
    dev = FakeDevice(id="emulator-5554", procs=[FakeProc(1, "p")])
    monkeypatch.setattr(devices_mod, "get_device", lambda _id: dev)
    omitted = json.loads(await T.enumerate_processes())
    explicit = json.loads(await T.enumerate_processes(device_id="emulator-5554"))
    assert omitted["source"] == explicit["source"]


@pytest.mark.asyncio
async def test_enumerate_applications_uses_identifier_as_glance_value(monkeypatch):
    dev = FakeDevice(apps=[FakeApp("com.x.y", "Y App", 0)])
    monkeypatch.setattr(devices_mod, "get_device", lambda _id: dev)
    res = json.loads(await T.enumerate_applications(device_id="emulator-5554"))
    assert res["source"] == "enumerate_applications:device=emulator-5554"
    found = json.loads(await T.search_capture(SNAPSHOT_HANDLE, field="source",
                                              contains=res["source"]))
    assert found["matches"][0]["summary"] == "com.x.y"


@pytest.mark.asyncio
async def test_enumerate_applications_local_device_short_circuits(monkeypatch):
    dev = FakeDevice(type="local", id="local")
    monkeypatch.setattr(devices_mod, "get_device", lambda _id: dev)
    res = json.loads(await T.enumerate_applications())
    assert res["total"] == 0
    assert "not supported" in res["summary"]
    assert res.get("error") is not True


@pytest.mark.asyncio
async def test_enumerate_processes_error_path(monkeypatch):
    def boom(_id):
        raise RuntimeError("device not found")
    monkeypatch.setattr(devices_mod, "get_device", boom)
    res = json.loads(await T.enumerate_processes(device_id="nope"))
    assert res["error"] is True
    assert "enumerate_processes failed" in res["summary"]


@pytest.mark.asyncio
async def test_enumerate_applications_error_path(monkeypatch):
    def boom(_id):
        raise RuntimeError("device not found")
    monkeypatch.setattr(devices_mod, "get_device", boom)
    res = json.loads(await T.enumerate_applications(device_id="nope"))
    assert res["error"] is True
    assert "enumerate_applications failed" in res["summary"]
