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
    ToolSpec("list_sessions", "low",
             "List live attach sessions with a real liveness probe. Returns "
             "session_id, pid, name, and live (bool) per session. Call this at "
             "the start of any turn that will act on a session - never assume a "
             "session_id from earlier in the conversation is still attached.",
             dict(_OBJ)),
    ToolSpec("detach", "medium",
             "Detach a live session and tear down its capture state. Errors "
             "only if the session_id is unknown.",
             _in(session_id={"type": "string"})),
    ToolSpec("enumerate_processes", "low",
             "List processes running on a device into the @snapshots store. "
             "Device-scoped: needs no attach/session - pass device_id (or omit "
             "for the sole USB device). Returns a source key; read results with "
             "search_capture(session_id='@snapshots', field='source', contains=<key>).",
             _in(device_id={"type": "string"})),
    ToolSpec("enumerate_applications", "low",
             "List installed apps/packages on a device into the @snapshots store. "
             "Device-scoped: no attach needed. 'identifier' is the package name. "
             "Returns a source key; read with search_capture(session_id='@snapshots', "
             "field='source', contains=<key>).",
             _in(device_id={"type": "string"})),
    ToolSpec("enumerate_modules", "low", "List modules loaded in an ATTACHED process (requires session_id from attach).",
             _in(session_id={"type": "string"}, filter={"type": "string"})),
    ToolSpec("enumerate_exports", "low", "List exports of a module in an ATTACHED process (requires session_id from attach).",
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
    ToolSpec("search_capture", "low",
             "Search captured events for a session, or device snapshots via the "
             "reserved handle '@snapshots'. Returns lean, byte-bounded matches "
             "and the true total. Use count_only=true to get just the count, "
             "limit=N to peek at a spread sample of N rows, and a more specific "
             "text= to narrow; read_capture(seq) for one full record.",
             _in(session_id={"type": "string"}, field={"type": "string"},
                 contains={"type": "string"}, text={"type": "string"},
                 byte_budget={"type": "integer"}, limit={"type": "integer"},
                 count_only={"type": "boolean"})),
    ToolSpec("read_capture", "low", "Read a captured record slice for a session, or a device snapshot record via the reserved handle '@snapshots'.",
             _in(session_id={"type": "string"}, seq={"type": "integer"},
                 offset={"type": "integer"}, byte_budget={"type": "integer"})),
    ToolSpec("page_capture", "low",
             "Read ALL rows of a snapshot from a capture store (COMPLETE, not "
             "sampled) for human display via the /snapshot command. "
             "session_id='@snapshots'; omit source for the latest snapshot, or "
             "pass source=<key> with field='summary', contains=<substring> to "
             "filter; list_sources=true returns the catalog. Models should use "
             "search_capture instead (this returns unbounded output).",
             _in(session_id={"type": "string"}, source={"type": "string"},
                 field={"type": "string"}, contains={"type": "string"},
                 list_sources={"type": "boolean"})),
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
