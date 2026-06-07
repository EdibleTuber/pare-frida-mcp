from pare_frida_mcp.contract import (
    CONTRACT_VERSION, TOOL_SPECS, WorkerContractAdapter,
)

def test_every_tool_has_required_metadata():
    for spec in TOOL_SPECS:
        assert spec.name
        assert spec.risk_tier in {"low", "medium", "high", "critical"}
        assert spec.input_schema.get("type") == "object"
        assert spec.output_schema.get("type") == "object"

def test_execute_script_is_critical_and_write_memory_high():
    by_name = {s.name: s for s in TOOL_SPECS}
    assert by_name["execute_script"].risk_tier == "critical"
    assert by_name["write_memory"].risk_tier == "high"

def test_read_memory_and_java_hook_are_high():
    by_name = {s.name: s for s in TOOL_SPECS}
    assert by_name["read_memory"].risk_tier == "high"
    assert by_name["java_hook"].risk_tier == "high"

def test_adapter_matches_agent_core_shape():
    adapter = WorkerContractAdapter()
    assert isinstance(adapter.contract_version(), int)
    tools = adapter.list_tools()
    for t in tools:
        assert {"name", "risk_tier", "input_schema", "output_schema"} <= set(t)

def test_capture_tools_document_snapshot_handle():
    by_name = {s.name: s for s in TOOL_SPECS}
    assert "@snapshots" in by_name["search_capture"].description
    assert "@snapshots" in by_name["read_capture"].description
