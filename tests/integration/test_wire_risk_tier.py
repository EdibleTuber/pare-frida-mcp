import pytest

from pare_frida_mcp.server import build_server
from pare_frida_mcp.contract import TOOL_SPECS
from agent_core.workers.risk import RISK_TIER_META_KEY


@pytest.mark.asyncio
async def test_every_tool_advertises_its_contract_tier_in_meta():
    server = build_server()
    tools = await server.list_tools()          # FastMCP in-process tool list
    by_name = {t.name: t for t in tools}
    expected = {s.name: s.risk_tier for s in TOOL_SPECS}
    for name, tier in expected.items():
        meta = getattr(by_name[name], "meta", None) or {}
        assert meta.get(RISK_TIER_META_KEY) == tier, (
            f"{name} should advertise {tier} in _meta, got {meta!r}"
        )
