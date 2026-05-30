from __future__ import annotations
from typing import Any


def enumerate_modules(script, filter: str | None = None) -> list[dict]:
    return script.exports_sync.modules(filter or "")


def enumerate_exports(script, module: str) -> list[dict]:
    return script.exports_sync.exports(module)


def read_memory(script, address: str, size: int) -> bytes:
    return script.exports_sync.mem_read(address, size)


def scan_memory(script, pattern: str, ranges: list | None = None) -> list:
    # v1 limitation: pattern scan via Process.findRangesByProtection is fast-follow.
    # Provide a thin pass-through; full implementation lands when needed.
    raise NotImplementedError("scan_memory: deferred to fast-follow")


def write_memory(script, address: str, hex_bytes: str) -> dict:
    return script.exports_sync.mem_write(address, hex_bytes)
