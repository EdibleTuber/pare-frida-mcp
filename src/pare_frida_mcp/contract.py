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
             "List modules loaded in an ATTACHED process. Returns the full module "
             "list. Omit session_id to target the most-recent live session.",
             _in(session_id={"type": "string"})),
    ToolSpec("enumerate_exports", "low",
             "List a module's exports in an ATTACHED process. Returns the full "
             "export list. Omit session_id to target the most-recent live session.",
             _in(session_id={"type": "string"}, module={"type": "string"})),
    ToolSpec("enumerate_classes", "low",
             "List LOADED Java classes in an ATTACHED process, filtered by "
             "CASE-INSENSITIVE substring. The filter matches the loaded Java "
             "PACKAGE, which can differ (including case) from the application id "
             "shown by enumerate_applications / '/apps' - e.g. app id "
             "'sg.vp.owasp_mobile.omtg_android' vs class package "
             "'sg.vp.owasp_mobile.OMTG_Android'. When unsure, filter on a short "
             "distinctive token. Classes load lazily - navigate into the "
             "screen/activity you care about first, then enumerate. Returns the "
             "loaded class list (capped at 500; the summary flags when capped - "
             "refine the filter). Omit session_id to target the most-recent live "
             "session.",
             _in(session_id={"type": "string"}, filter={"type": "string"})),
    ToolSpec("enumerate_methods", "low",
             "List a Java class's DECLARED methods in an ATTACHED process. "
             "Declared-only (excludes inherited framework methods). Returns "
             "{name, signature} per method; signature carries parameter types for "
             "java_hook overload resolution. Omit session_id to target the "
             "most-recent live session.",
             _in(session_id={"type": "string"}, cls={"type": "string"})),
    ToolSpec("load_script", "medium", "Load a bundled script export set.",
             _in(session_id={"type": "string"}, name={"type": "string"})),
    ToolSpec("execute_script", "critical",
             "Evaluate arbitrary JS in an attached session - a NATIVE / Process / "
             "Memory escape hatch AND a pure-JS compute sandbox. It runs in a bare "
             "QuickJS runtime: NO Java (or ObjC) bridge - Frida 17 removed the "
             "`Java` global, so any script referencing `Java` fails with 'Java is "
             "not defined' - and NO browser/DOM globals (`atob`, `btoa`, `fetch`, "
             "`window`). For Java work use enumerate_classes / enumerate_methods / "
             "java_hook instead, which run in the bundled agent that DOES load the "
             "bridge. For offline byte math / decoding (Base64, hex, XOR), write "
             "plain JS - implement your own decoder - which runs here fine without "
             "any bridge. The script's completion value - the value of its last "
             "statement, e.g. the return of a trailing `solve()` - comes back as "
             "`value`; you do NOT need to `send()` it (use `send()` only for "
             "intermediate/streamed output). Omit session_id to target the "
             "most-recent live session.",
             _in(session_id={"type": "string"}, source={"type": "string"})),
    ToolSpec("java_hook", "high",
             "Install an OBSERVING Java method hook (captures decoded arguments "
             "AND the return value; the original still runs). Works on app and "
             "framework classes. 'overload' is an ordered list of frida type "
             "descriptors, one per parameter (e.g. [\"[B\",\"int\",\"int\"]); "
             "omit it for a non-overloaded method - if the method is overloaded "
             "the call returns the available descriptor lists to choose from. "
             "Read what the hook captured with read_hook_events (start at the "
             "since_seq this call returns). WARNING: hooking an ultra-hot method "
             "(e.g. String.<init>) floods the buffer; a per-thread guard prevents "
             "recursion but the signal will be noisy.",
             _in(session_id={"type": "string"}, cls={"type": "string"},
                 method={"type": "string"},
                 overload={"type": "array", "items": {"type": "string"}})),
    ToolSpec("java_hook_remove", "low", "Remove a previously installed Java method "
             "hook. 'overload' is the same descriptor list used to install it.",
             _in(session_id={"type": "string"}, cls={"type": "string"},
                 method={"type": "string"},
                 overload={"type": "array", "items": {"type": "string"}})),
    ToolSpec("read_hook_events", "low",
             "Read buffered java_hook events for a session (non-destructive). "
             "Pass since_seq = the last seq you saw (0 first time); returns "
             "events with seq > since_seq, decoded args + return value. "
             "has_more + next_seq means call again with since_seq=next_seq to "
             "page the rest; lost>0 means old events were evicted (read more "
             "often / raise the buffer). An EMPTY result means the hooked action "
             "has not been triggered yet - retry after the app action, do not "
             "remove the hook. Tier low: the sensitive act (choosing what to "
             "capture) was already gated at java_hook.",
             _in(since_seq={"type": "integer"}, limit={"type": "integer"},
                 session_id={"type": "string"})),
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
