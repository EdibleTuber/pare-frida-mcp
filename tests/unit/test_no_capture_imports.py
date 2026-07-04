import importlib
import pytest


def test_capture_package_is_gone():
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("pare_frida_mcp.capture.store")
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("pare_frida_mcp.core.snapshots")
