from __future__ import annotations


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
