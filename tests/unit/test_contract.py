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

def test_tool_count_is_18():
    # 17 (+ enumerate_classes/methods) -> 18 (+ read_hook_events)
    assert len(TOOL_SPECS) == 18


def test_read_hook_events_is_low():
    by_name = {s.name: s for s in TOOL_SPECS}
    assert by_name["read_hook_events"].risk_tier == "low"

def test_execute_script_description_warns_no_java_bridge():
    # The bare ad-hoc script has no Java bridge (Frida 17 removed the global);
    # the tool spec must steer the model to the Java tools instead of writing
    # `Java.*` into execute_script and hitting "Java is not defined".
    desc = {s.name: s for s in TOOL_SPECS}["execute_script"].description.lower()
    assert "java" in desc and "bridge" in desc
    assert "enumerate_classes" in desc

def test_enumerate_classes_description_notes_case_insensitive_package():
    # Filter matches the loaded Java package, which can differ (incl. case) from
    # the application id shown in /apps; matching is case-insensitive.
    desc = {s.name: s for s in TOOL_SPECS}["enumerate_classes"].description.lower()
    assert "case-insensitive" in desc
