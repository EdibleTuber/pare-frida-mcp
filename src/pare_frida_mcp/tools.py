from __future__ import annotations

import json

from pare_frida_mcp.config import load_config
from pare_frida_mcp.core.sessions import SessionManager

# Single process-wide manager; real Frida wiring lands in a later task.
MANAGER = SessionManager(load_config())


async def list_devices() -> str:
    # Real frida enumeration lands in a later task; placeholder keeps the
    # MCP surface exercisable without a device.
    return json.dumps({"summary": "no device backend wired yet", "devices": []})
