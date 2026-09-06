import shutil

import pytest

from pare_worker_kit import RISK_TIER_META_KEY

from pare_frida_mcp.server import build_server
from pare_frida_mcp.contract import TOOL_SPECS

# agent_core is the DAEMON side. A machine that only runs this worker has no
# reason to install it -- that is the point of depending on pare-worker-kit
# instead -- so the checks that genuinely need agent_core's conformance
# helpers skip when it is absent, exactly as the sibling files in this
# directory already do.
pytest.importorskip(
    "agent_core.workers.conformance",
    reason="agent_core is the daemon side and is not needed to run a worker")
from agent_core.workers.conformance import assert_stdio_conformance   # noqa: E402
from agent_core.workers.types import WorkerSpec                       # noqa: E402


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


@pytest.mark.asyncio
async def test_worker_passes_live_stdio_conformance():
    # The real worker, spawned over stdio, must satisfy agent_core's wire
    # conformance — including the risk_tier-on-_meta assertion. assert_stdio_
    # conformance spawns the subprocess itself via the WorkerSpec command.
    if shutil.which("pare-frida-mcp") is None:
        pytest.skip("pare-frida-mcp console script not on PATH (venv/bin not active)")
    spec = WorkerSpec(
        name="frida",
        transport="stdio",
        command="pare-frida-mcp",   # console-script entry point of this package
        risk_default="high",
    )
    await assert_stdio_conformance(spec)   # raises AssertionError on any gap
