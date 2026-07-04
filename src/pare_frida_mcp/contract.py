from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

CONTRACT_VERSION = 1

_OBJ = {"type": "object", "properties": {}}
_BOUNDED_OUT = {"type": "object", "properties": {
    "summary": {"type": "string"},
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
    ToolSpec("list_sessions", "low",
             "List live attach sessions with a real liveness probe. Returns "
             "session_id, pid, name, and live (bool) per session. Call this at "
             "the start of any turn that will act on a session - never assume a "
             "session_id from earlier in the conversation is still attached.",
             dict(_OBJ)),
    ToolSpec("detach", "medium",
             "Detach a live session. Errors only if the session_id is unknown.",
             _in(session_id={"type": "string"})),
    ToolSpec("enumerate_processes", "low",
             "List processes running on a device. Device-scoped: needs no "
             "attach/session — pass device_id (or omit for the sole USB device). "
             "Returns the full process list.",
             _in(device_id={"type": "string"})),
    ToolSpec("enumerate_applications", "low",
             "List installed apps/packages on a device. Device-scoped: no attach "
             "needed. 'identifier' is the package name. Returns the full application list.",
             _in(device_id={"type": "string"})),
    ToolSpec("enumerate_modules", "low",
             "List modules loaded in an ATTACHED process (requires session_id "
             "from attach). Returns the full module list.",
             _in(session_id={"type": "string"})),
    ToolSpec("enumerate_exports", "low",
             "List a module's exports in an ATTACHED process (requires session_id "
             "from attach). Returns the full export list.",
             _in(session_id={"type": "string"}, module={"type": "string"})),
    ToolSpec("load_script", "medium", "Load a bundled script export set.",
             _in(session_id={"type": "string"}, name={"type": "string"})),
    ToolSpec("execute_script", "critical", "Evaluate arbitrary JS in a session.",
             _in(session_id={"type": "string"}, source={"type": "string"})),
    ToolSpec("java_hook", "high", "Install an observing Java method hook.",
             _in(session_id={"type": "string"}, cls={"type": "string"},
                 method={"type": "string"}, overload={"type": "string"})),
    ToolSpec("java_hook_remove", "low", "Remove a previously installed Java method hook.",
             _in(session_id={"type": "string"}, cls={"type": "string"},
                 method={"type": "string"}, overload={"type": "string"})),
    ToolSpec("read_memory", "high", "Read target memory (hex preview).",
             _in(session_id={"type": "string"}, address={"type": "string"},
                 size={"type": "integer"})),
    ToolSpec("write_memory", "high", "Write bytes to target memory.",
             _in(session_id={"type": "string"}, address={"type": "string"},
                 bytes={"type": "string"})),
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
