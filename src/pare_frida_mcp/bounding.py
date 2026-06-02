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


def page_items(items, offset=0, limit=0, byte_budget=4096, reserve=512):
    """Return (page, next_offset, truncated).

    Appends items starting at `offset` until adding another would push the
    serialized list past (byte_budget - reserve), or until `limit` items are
    collected (when limit > 0). Truncation happens at the item level so the
    surrounding JSON is always structurally valid. `reserve` leaves headroom
    for the response envelope (summary/total/offset/... keys). At least one
    item per page is emitted so pagination always makes forward progress.
    next_offset is the index to resume from, or None when nothing remains.
    """
    start = max(0, offset)
    budget = max(0, byte_budget - reserve)
    page = []
    size = 2  # the enclosing [] of the list
    for item in items[start:]:
        if limit and len(page) >= limit:
            break
        item_bytes = len(json.dumps(item).encode("utf-8")) + 1  # +1 for the comma
        if page and size + item_bytes > budget:
            break
        page.append(item)
        size += item_bytes
    consumed = start + len(page)
    truncated = consumed < len(items)
    next_offset = consumed if truncated else None
    return page, next_offset, truncated
