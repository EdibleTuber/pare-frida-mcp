from pare_frida_mcp.contract import TOOL_SPECS

EXPECTED_TOOLS = {
    "list_devices", "select_device", "attach", "list_sessions", "detach",
    "enumerate_processes", "enumerate_applications", "enumerate_modules",
    "enumerate_exports", "enumerate_classes", "enumerate_methods", "load_script",
    "execute_script", "java_hook", "java_hook_remove", "read_hook_events",
    "read_memory", "write_memory", "java_read_fields",
}


def test_tool_surface_matches_expected():
    assert {s.name for s in TOOL_SPECS} == EXPECTED_TOOLS
