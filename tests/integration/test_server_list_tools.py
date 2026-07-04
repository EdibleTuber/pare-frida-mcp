from pare_frida_mcp.contract import TOOL_SPECS


def test_tool_count_is_15_and_capture_tools_gone():
    # 18 → 15: three capture-retrieval tools have been removed
    assert len(TOOL_SPECS) == 15
