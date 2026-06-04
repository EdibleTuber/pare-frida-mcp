from pare_frida_mcp.core import devices as devices_mod


class FakeProc:
    def __init__(self, pid, name):
        self.pid, self.name = pid, name


class FakeApp:
    def __init__(self, identifier, name, pid):
        self.identifier, self.name, self.pid = identifier, name, pid


class FakeDevice:
    def __init__(self, type="usb", procs=(), apps=()):
        self.type = type
        self.id = "emulator-5554"
        self._procs = list(procs)
        self._apps = list(apps)
        self.scope_used = "UNSET"

    def enumerate_processes(self):
        return self._procs

    def enumerate_applications(self, scope=None):
        self.scope_used = scope
        return self._apps


def test_processes_mapped_and_sorted_case_insensitively():
    dev = FakeDevice(procs=[FakeProc(2, "Zebra"), FakeProc(1, "alpha"), FakeProc(3, "Beta")])
    res = devices_mod.enumerate_processes(dev)
    assert [p["name"] for p in res] == ["alpha", "Beta", "Zebra"]
    assert res[0] == {"pid": 1, "name": "alpha"}


def test_processes_none_name_does_not_crash():
    dev = FakeDevice(procs=[FakeProc(1, None), FakeProc(2, "init")])
    res = devices_mod.enumerate_processes(dev)  # None name must not raise on sort
    assert {p["pid"] for p in res} == {1, 2}


def test_applications_mapped_sorted_by_identifier_and_request_minimal_scope():
    dev = FakeDevice(apps=[
        FakeApp("org.other.thing", "Other", 1234),
        FakeApp("com.example.app", "Cool App", 0),
    ])
    res = devices_mod.enumerate_applications(dev)
    assert [a["identifier"] for a in res] == ["com.example.app", "org.other.thing"]
    assert res[0] == {"identifier": "com.example.app", "name": "Cool App", "pid": 0}
    assert dev.scope_used == "minimal"  # scope kwarg drives Frida fetch cost


def test_applications_fallback_when_scope_kwarg_unsupported():
    class NoScopeDevice:
        type = "usb"
        id = "emulator-5554"

        def enumerate_applications(self, *args, **kwargs):
            if "scope" in kwargs:
                raise TypeError("enumerate_applications() got an unexpected keyword argument 'scope'")
            return [FakeApp("com.a.b", "AB", 0)]

    res = devices_mod.enumerate_applications(NoScopeDevice())
    assert res == [{"identifier": "com.a.b", "name": "AB", "pid": 0}]
