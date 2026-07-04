import json
import pytest

from pare_frida_mcp import tools as T
from pare_frida_mcp.core import devices as devices_mod
from pare_frida_mcp.core import memory as memory_mod
from pare_frida_mcp.ids import new_session_id


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


class _DummySession:
    """Minimal stand-in for a live Session for enumerate_modules/exports tests."""
    def __init__(self):
        self.script = object()
        self.frida_session = None

    def flush(self):
        pass


# ---------------------------------------------------------------------------
# enumerate_processes
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_enumerate_processes_returns_full_list(monkeypatch):
    dev = FakeDevice(procs=[FakeProc(1, "init"), FakeProc(9, "zygote")])
    monkeypatch.setattr(devices_mod, "get_device", lambda _id: dev)
    out = await T.enumerate_processes("")
    doc = json.loads(out)
    assert "processes" in doc
    assert len(doc["processes"]) == 2
    assert doc["summary"] == "2 processes"
    assert "store" not in doc
    assert doc.get("error") is not True


@pytest.mark.asyncio
async def test_enumerate_processes_list_contents(monkeypatch):
    dev = FakeDevice(procs=[FakeProc(1, "init"), FakeProc(9, "zygote")])
    monkeypatch.setattr(devices_mod, "get_device", lambda _id: dev)
    doc = json.loads(await T.enumerate_processes(device_id="emulator-5554"))
    assert {p["pid"] for p in doc["processes"]} == {1, 9}
    assert "source" not in doc


@pytest.mark.asyncio
async def test_enumerate_processes_error_path(monkeypatch):
    def boom(_id):
        raise RuntimeError("device not found")
    monkeypatch.setattr(devices_mod, "get_device", boom)
    res = json.loads(await T.enumerate_processes(device_id="nope"))
    assert res["error"] is True
    assert "enumerate_processes failed" in res["summary"]


# ---------------------------------------------------------------------------
# enumerate_applications
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_enumerate_applications_returns_full_list(monkeypatch):
    dev = FakeDevice(type="usb", apps=[FakeApp("com.x.y", "Y App", 0)])
    monkeypatch.setattr(devices_mod, "get_device", lambda _id: dev)
    doc = json.loads(await T.enumerate_applications(device_id="emulator-5554"))
    assert "applications" in doc
    assert len(doc["applications"]) == 1
    assert doc["applications"][0]["identifier"] == "com.x.y"
    assert "store" not in doc
    assert "source" not in doc
    assert doc.get("error") is not True


@pytest.mark.asyncio
async def test_enumerate_applications_local_device_short_circuits(monkeypatch):
    dev = FakeDevice(type="local", id="local")
    monkeypatch.setattr(devices_mod, "get_device", lambda _id: dev)
    res = json.loads(await T.enumerate_applications())
    assert res["applications"] == []
    assert "not supported" in res["summary"]
    assert res.get("error") is not True
    assert "store" not in res


@pytest.mark.asyncio
async def test_enumerate_applications_error_path(monkeypatch):
    def boom(_id):
        raise RuntimeError("device not found")
    monkeypatch.setattr(devices_mod, "get_device", boom)
    res = json.loads(await T.enumerate_applications(device_id="nope"))
    assert res["error"] is True
    assert "enumerate_applications failed" in res["summary"]


# ---------------------------------------------------------------------------
# enumerate_modules
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_enumerate_modules_returns_full_list(monkeypatch):
    sid = new_session_id()
    T.MANAGER._sessions[sid] = _DummySession()
    mods = [{"name": f"lib{i}.so", "base": hex(i), "size": i} for i in range(5)]
    monkeypatch.setattr(memory_mod, "enumerate_modules", lambda script: mods)
    doc = json.loads(await T.enumerate_modules(sid))
    assert "modules" in doc
    assert doc["modules"] == mods
    assert doc["summary"] == "5 modules"
    assert "store" not in doc
    assert "source" not in doc
    assert doc.get("error") is not True


@pytest.mark.asyncio
async def test_enumerate_modules_no_live_session_errors():
    sid = new_session_id()  # well-formed but never registered
    res = json.loads(await T.enumerate_modules(sid))
    assert res.get("error") is True


@pytest.mark.asyncio
async def test_enumerate_modules_empty_list(monkeypatch):
    sid = new_session_id()
    T.MANAGER._sessions[sid] = _DummySession()
    monkeypatch.setattr(memory_mod, "enumerate_modules", lambda script: [])
    res = json.loads(await T.enumerate_modules(sid))
    assert res.get("error") is not True
    assert res["modules"] == []
    assert "0 modules" in res["summary"]


# ---------------------------------------------------------------------------
# enumerate_exports
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_enumerate_exports_returns_full_list(monkeypatch):
    sid = new_session_id()
    T.MANAGER._sessions[sid] = _DummySession()
    exps = [{"name": f"sym{i}", "address": hex(i)} for i in range(3)]
    monkeypatch.setattr(memory_mod, "enumerate_exports", lambda script, module: exps)
    doc = json.loads(await T.enumerate_exports(sid, module="libc.so"))
    assert "exports" in doc
    assert doc["exports"] == exps
    assert "3 exports for libc.so" in doc["summary"]
    assert "store" not in doc
    assert "source" not in doc
    assert doc.get("error") is not True


@pytest.mark.asyncio
async def test_enumerate_exports_no_live_session_errors():
    sid = new_session_id()
    res = json.loads(await T.enumerate_exports(sid, module="libc.so"))
    assert res.get("error") is True


@pytest.mark.asyncio
async def test_enumerate_exports_module_in_summary(monkeypatch):
    sid = new_session_id()
    T.MANAGER._sessions[sid] = _DummySession()
    monkeypatch.setattr(memory_mod, "enumerate_exports",
                        lambda script, module: [{"name": "malloc"}])
    doc = json.loads(await T.enumerate_exports(sid, module="libm.so"))
    assert "libm.so" in doc["summary"]
    assert doc["exports"][0]["name"] == "malloc"
