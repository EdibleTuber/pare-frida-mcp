from __future__ import annotations
import json
from typing import Any

from pare_frida_mcp.agent_bundle import load_agent_js


def load_bundled_script(frida_session) -> Any:
    """Create a Frida Script from the bundled agent JS and load it."""
    script = frida_session.create_script(load_agent_js())
    script.load()
    return script


def execute_ad_hoc(frida_session, source: str) -> dict[str, Any]:
    """Evaluate arbitrary JS in a new short-lived script in the same session and
    return an honest record of everything it produced:

        {"sends": [...payloads...], "logs": [...console.log lines...],
         "value": <completion value or None>, "error": str|None}

    `value` is the source's completion value — the value of its last statement,
    e.g. the return of a trailing `solve()`. Frida's `script.load()` does not hand
    the host a bare expression's value, so we wrap the source in an indirect `eval`
    and auto-`send()` a marked result; the model therefore does NOT have to remember
    to `send()` its answer (it wrote `solve();` and saw nothing before). The marked
    result is routed to `value`, never mixed into user `sends`.

    Note: this is a BARE script with no Java bridge. On Frida 17 the `Java`/`ObjC`
    globals were removed, so a script referencing `Java` raises
    `ReferenceError: 'Java' is not defined` — surfaced here as `error`, never
    swallowed. Java work belongs in the bundled-agent rpc exports, not here; this
    stays a native/Process/Memory escape hatch. `console.log` is delivered to the
    log handler (not on('message')), so we capture it separately."""
    wrapped = (
        "var __v = (0,eval)(%s); "
        "send({__adhoc_result__: true, value: (typeof __v === 'undefined' ? null : __v)});"
        % json.dumps(source)
    )
    script = frida_session.create_script(wrapped)
    sends: list[Any] = []
    logs: list[str] = []
    state: dict[str, Any] = {"error": None, "value": None}

    def on_message(message, data):
        kind = message.get("type")
        if kind == "send":
            payload = message.get("payload")
            if isinstance(payload, dict) and payload.get("__adhoc_result__"):
                state["value"] = payload.get("value")
            else:
                sends.append(payload)
        elif kind == "error":
            state["error"] = message.get("description") or "script error"

    script.on("message", on_message)
    set_log = getattr(script, "set_log_handler", None)
    if set_log is not None:
        set_log(lambda level, text: logs.append(text))
    script.load()
    script.unload()
    return {"sends": sends, "logs": logs, "value": state["value"], "error": state["error"]}
