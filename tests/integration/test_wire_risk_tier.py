import asyncio
import shutil

import pytest

from pare_worker_kit import PRODUCES_META_KEY, RISK_TIER_META_KEY

from pare_frida_mcp.contract import TOOL_SPECS
from pare_frida_mcp.server import build_server


def _wire_tools():
    """The tool list as the daemon actually sees it, via FastMCP."""
    server = build_server()
    return {t.name: t for t in asyncio.run(server.list_tools())}


# The checks below need pare-worker-kit and nothing else, which is the whole
# point of a worker depending on the kit rather than on the daemon. They are
# deliberately NOT behind an agent_core importorskip: this module used to
# carry one at module scope, and it skipped the entire file on every machine
# without agent_core -- including CI, where the run reported
# "128 items / 1 skipped" and the name test_wire_risk_tier appeared nowhere in
# the log. The one test that genuinely needs the daemon guards itself, below.


def test_build_server_advertises_risk_tier_over_the_wire():
    by_name = _wire_tools()
    assert {s.name for s in TOOL_SPECS} == set(by_name)
    for spec in TOOL_SPECS:
        assert by_name[spec.name].meta[RISK_TIER_META_KEY] == spec.risk_tier


def test_build_server_advertises_produces_over_the_wire():
    by_name = _wire_tools()
    for spec in TOOL_SPECS:
        assert by_name[spec.name].meta[PRODUCES_META_KEY] == spec.produces


def test_wire_meta_carries_the_contract_keys_and_nothing_else():
    """A stray _meta key is an unreviewed addition to the wire contract.

    Deliberately exact, where the two assertions above are per-key. Adding a
    third contract key changes what every worker in the fleet advertises to
    the daemon, so it should fail here and be made on purpose rather than
    inherited from whatever a library decided to attach.
    """
    for tool in _wire_tools().values():
        assert set(tool.meta) == {RISK_TIER_META_KEY, PRODUCES_META_KEY}


@pytest.mark.asyncio
async def test_worker_passes_live_stdio_conformance():
    # The real worker, spawned over stdio, must satisfy agent_core's wire
    # conformance. agent_core is the DAEMON side: a machine that only runs
    # this worker has no reason to install it, so this single test guards
    # itself here rather than at module scope, where the guard would take the
    # kit-only checks above down with it.
    pytest.importorskip(
        "agent_core.workers.conformance",
        reason="agent_core is the daemon side and is not needed to run a worker")
    from agent_core.workers.conformance import assert_stdio_conformance
    from agent_core.workers.types import WorkerSpec

    if shutil.which("pare-frida-mcp") is None:
        pytest.skip("pare-frida-mcp console script not on PATH (venv/bin not active)")
    spec = WorkerSpec(
        name="frida",
        transport="stdio",
        command="pare-frida-mcp",   # console-script entry point of this package
        risk_default="high",
    )
    await assert_stdio_conformance(spec)   # raises AssertionError on any gap
