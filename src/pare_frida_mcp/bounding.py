from __future__ import annotations

import json


def bound_text(text: str, max_bytes: int) -> tuple[str, bool]:
    """Return (text, truncated). Truncates on a UTF-8 char boundary so the
    result is always valid UTF-8 and never exceeds max_bytes."""
    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return text, False
    clipped = encoded[:max_bytes]
    # Back off to the last complete codepoint.
    text_out = clipped.decode("utf-8", errors="ignore")
    return text_out, True


def fit_items(items, byte_budget=4096, reserve=512):
    """Return (fitted, fully_fit). Append whole items until adding another
    would push the serialized list past (byte_budget - reserve). `reserve`
    leaves headroom for the response envelope (summary/total/... keys).
    Truncation is at the item level, so the surrounding JSON is always valid.
    At least one item is returned when any exist, to guarantee forward
    progress/visibility. fully_fit is True iff every item fit.
    """
    budget = max(0, byte_budget - reserve)
    fitted = []
    size = 2  # the enclosing [] of the list
    for item in items:
        item_bytes = len(json.dumps(item).encode("utf-8")) + 1  # +1 for the comma
        if fitted and size + item_bytes > budget:
            break
        fitted.append(item)
        size += item_bytes
    return fitted, len(fitted) == len(items)
