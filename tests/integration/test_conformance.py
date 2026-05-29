import pytest

from pare_frida_mcp.contract import WorkerContractAdapter

def test_assert_conformance_passes():
    conformance = pytest.importorskip("agent_core.workers.conformance")
    conformance.assert_conformance(WorkerContractAdapter())
