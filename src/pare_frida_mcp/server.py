from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from pare_frida_mcp.contract import TOOL_SPECS
from pare_frida_mcp import tools as tools_mod


def build_server() -> FastMCP:
    server = FastMCP("pare-frida-mcp")
    for spec in TOOL_SPECS:
        handler = getattr(tools_mod, spec.name, None)
        if handler is None:
            handler = _stub_for(spec.name)
        server.add_tool(handler, name=spec.name, description=spec.description)
    return server


def _stub_for(name: str):
    async def _stub(**kwargs) -> str:
        import json
        return json.dumps({"summary": f"{name} not implemented in this build"})
    _stub.__name__ = name
    return _stub


def main() -> None:
    build_server().run(transport="stdio")
