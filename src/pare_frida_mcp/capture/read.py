from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pare_frida_mcp.bounding import bound_text
from pare_frida_mcp.capture.store import CaptureStore


def read_capture(store: CaptureStore, *, seq: int, offset: int = 0,
                 byte_budget: int = 4096) -> dict[str, Any]:
    row = store.get(seq)
    if row is None:
        raise ValueError(f"no capture record seq={seq}")
    row_view = dict(row)
    # If the payload was spilled to a blob, restore it for the response so
    # callers get the same shape whether or not spill happened.
    if row_view.get("payload") is None and row_view.get("blob_ref"):
        try:
            row_view["payload"] = Path(row_view["blob_ref"]).read_text(encoding="utf-8")
        except OSError:
            pass  # blob missing/unreadable: leave payload null, caller sees blob_ref
    # Operate on bytes throughout so offset/next_offset are consistently byte-indexed.
    full_bytes = json.dumps(row_view).encode("utf-8")
    window_bytes = full_bytes[offset:]
    window_text = window_bytes.decode("utf-8", errors="ignore")
    text, truncated = bound_text(window_text, byte_budget)
    consumed = len(text.encode("utf-8"))
    return {"seq": seq, "offset": offset, "truncated": truncated,
            "next_offset": offset + consumed if truncated else None,
            "text": text}
