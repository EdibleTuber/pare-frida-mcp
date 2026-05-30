from __future__ import annotations
from typing import Any

from pare_frida_mcp.agent_bundle import load_agent_js


def load_bundled_script(frida_session) -> Any:
    """Create a Frida Script from the bundled agent JS and load it."""
    script = frida_session.create_script(load_agent_js())
    script.load()
    return script


def execute_ad_hoc(frida_session, source: str) -> Any:
    """Evaluate arbitrary JS in a new short-lived script in the same session,
    returning whatever the script's main expression sends back via send()."""
    # Run inside the existing session so it shares process context.
    script = frida_session.create_script(source)
    result: dict[str, Any] = {"value": None}

    def on_message(message, data):
        if message.get("type") == "send":
            result["value"] = message.get("payload")

    script.on("message", on_message)
    script.load()
    script.unload()
    return result["value"]
