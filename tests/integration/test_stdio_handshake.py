"""End-to-end stdio handshake test.

Launches the pare-frida-mcp console script as a subprocess via agent_core's
real MCPClient (stdio transport), performs the full MCP initialize +
tools/list round-trip, and asserts the contract tools are present.

Skips cleanly if:
  - agent_core is not importable (not installed in the active venv)
  - the pare-frida-mcp console script is not on PATH

These conditions mean the PARE integration environment isn't configured, so
the test is not meaningful to run.
"""
from __future__ import annotations

import shutil

import pytest


@pytest.mark.asyncio
async def test_stdio_handshake_lists_tools():
    client_mod = pytest.importorskip("agent_core.workers.client")

    if shutil.which("pare-frida-mcp") is None:
        pytest.skip("pare-frida-mcp console script not found on PATH")

    client = client_mod.MCPClient(command="pare-frida-mcp")
    await client.connect()
    try:
        await client.initialize()
        result = await client.list_tools()
        names = {t.name for t in result.tools}
        assert "execute_script" in names, f"execute_script missing from tools: {names}"
        assert "list_devices" in names, f"list_devices missing from tools: {names}"
    finally:
        await client.close()
