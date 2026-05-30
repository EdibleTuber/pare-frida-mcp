from __future__ import annotations
from pathlib import Path

_BUNDLE = Path(__file__).parent / "agent" / "dist" / "agent.js"

def load_agent_js() -> str:
    return _BUNDLE.read_text(encoding="utf-8")
