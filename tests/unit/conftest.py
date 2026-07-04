"""Unit-test conftest: inject a minimal frida stub so tests that import
tools.py (which pulls in core.devices → frida) work without the native
Frida wheel installed.  Only the names used at module-import time are
stubbed; test logic that actually calls Frida functions should use the
device/ integration suite instead."""
from __future__ import annotations

import sys
import types

import pytest

if "frida" not in sys.modules:
    _frida_stub = types.ModuleType("frida")
    _frida_stub.enumerate_devices = lambda: []
    _frida_stub.get_device = lambda *a, **kw: None
    _frida_stub.get_usb_device = lambda *a, **kw: None
    sys.modules["frida"] = _frida_stub


@pytest.fixture(autouse=True)
def _fresh_manager():
    """Rebind the process-global SessionManager to a clean instance per test so
    sessions injected by one test can't leak into another."""
    import pare_frida_mcp.tools as tools_mod
    from pare_frida_mcp.core.sessions import SessionManager

    tools_mod.MANAGER = SessionManager(tools_mod.CFG)
    yield
