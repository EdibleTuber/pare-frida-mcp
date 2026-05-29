import pytest
from pare_frida_mcp.server import build_server


@pytest.mark.asyncio
async def test_list_tools_exposes_all_contract_tools():
    server = build_server()
    tools = await server.list_tools()
    names = {t.name for t in tools}
    assert {"list_devices", "attach", "execute_script", "write_memory",
            "search_capture", "read_capture"} <= names
