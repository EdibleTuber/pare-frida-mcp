from __future__ import annotations

import json
from typing import Any

from pare_frida_mcp.bounding import bound_text
from pare_frida_mcp.capture.store import CaptureStore


def read_capture(store: CaptureStore, *, seq: int, offset: int = 0,
                 byte_budget: int = 4096) -> dict[str, Any]:
    row = store.get(seq)
    if row is None:
        raise ValueError(f"no capture record seq={seq}")
    full = json.dumps({k: row[k] for k in row})
    window = full[offset:]
    text, truncated = bound_text(window, byte_budget)
    return {"seq": seq, "offset": offset, "truncated": truncated,
            "next_offset": offset + len(text.encode("utf-8")) if truncated else None,
            "text": text}
