"""Unit-test conftest: inject a minimal frida stub so tests that import
tools.py (which pulls in core.devices → frida) work without the native
Frida wheel installed.  Only the names used at module-import time are
stubbed; test logic that actually calls Frida functions should use the
device/ integration suite instead."""
from __future__ import annotations

import sys
import types

if "frida" not in sys.modules:
    _frida_stub = types.ModuleType("frida")
    _frida_stub.enumerate_devices = lambda: []
    _frida_stub.get_device = lambda *a, **kw: None
    _frida_stub.get_usb_device = lambda *a, **kw: None
    sys.modules["frida"] = _frida_stub
