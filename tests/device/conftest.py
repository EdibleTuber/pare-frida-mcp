import pytest

@pytest.fixture(scope="session")
def usb_device():
    import frida
    try:
        d = frida.get_usb_device(timeout=2)
    except Exception as e:
        pytest.skip(f"no USB Frida device available: {e}")
    yield d


@pytest.fixture()
def system_server_pid(usb_device):
    for p in usb_device.enumerate_processes():
        if p.name == "system_server":
            return p.pid
    pytest.skip("system_server not found on device")
