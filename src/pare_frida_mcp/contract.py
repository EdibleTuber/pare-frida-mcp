from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

CONTRACT_VERSION = 1

_OBJ = {"type": "object", "properties": {}}
_BOUNDED_OUT = {"type": "object", "properties": {
    "summary": {"type": "string"},
    "capture": {"type": "object"},
}}


@dataclass(frozen=True)
class ToolSpec:
    name: str
    risk_tier: str
    description: str
    input_schema: dict[str, Any]
    output_schema: dict[str, Any] = field(default_factory=lambda: dict(_BOUNDED_OUT))
    handler: Callable[..., Any] | None = None


def _in(**props) -> dict[str, Any]:
    return {"type": "object", "properties": props}


TOOL_SPECS: list[ToolSpec] = [
    ToolSpec("list_devices", "low", "List Frida devices.", dict(_OBJ)),
    ToolSpec("select_device", "low", "Select a device by id.",
             _in(device_id={"type": "string"})),
    ToolSpec("attach", "medium", "Attach to a process by pid or name.",
             _in(device_id={"type": "string"}, target={"type": "string"})),
    ToolSpec("enumerate_modules", "low", "List loaded modules.",
             _in(session_id={"type": "string"}, filter={"type": "string"})),
    ToolSpec("enumerate_exports", "low", "List exports of a module.",
             _in(session_id={"type": "string"}, module={"type": "string"})),
    ToolSpec("load_script", "medium", "Load a bundled script export set.",
             _in(session_id={"type": "string"}, name={"type": "string"})),
    ToolSpec("execute_script", "critical", "Evaluate arbitrary JS in a session.",
             _in(session_id={"type": "string"}, source={"type": "string"})),
    ToolSpec("java_hook", "medium", "Install an observing Java method hook.",
             _in(session_id={"type": "string"}, cls={"type": "string"},
                 method={"type": "string"}, overload={"type": "string"})),
    ToolSpec("read_memory", "medium", "Read target memory (hex preview).",
             _in(session_id={"type": "string"}, address={"type": "string"},
                 size={"type": "integer"})),
    ToolSpec("scan_memory", "medium", "Scan memory for a byte pattern.",
             _in(session_id={"type": "string"}, pattern={"type": "string"})),
    ToolSpec("write_memory", "high", "Write bytes to target memory.",
             _in(session_id={"type": "string"}, address={"type": "string"},
                 bytes={"type": "string"})),
    ToolSpec("search_capture", "low", "Search captured events.",
             _in(session_id={"type": "string"}, field={"type": "string"},
                 contains={"type": "string"}, text={"type": "string"},
                 byte_budget={"type": "integer"})),
    ToolSpec("read_capture", "low", "Read a captured record slice.",
             _in(session_id={"type": "string"}, seq={"type": "integer"},
                 offset={"type": "integer"}, byte_budget={"type": "integer"})),
]


class WorkerContractAdapter:
    """Exposes the agent_core WorkerContract shape for assert_conformance."""

    def contract_version(self) -> int:
        return CONTRACT_VERSION

    def list_tools(self) -> list[dict[str, Any]]:
        return [
            {"name": s.name, "risk_tier": s.risk_tier,
             "input_schema": s.input_schema, "output_schema": s.output_schema}
            for s in TOOL_SPECS
        ]
