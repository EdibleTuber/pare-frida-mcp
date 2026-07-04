from __future__ import annotations


def java_hook(script, cls: str, method: str, overload: str | None = None) -> dict:
    return script.exports_sync.java_hook_install(cls, method, overload or "")


def enumerate_classes(script, filter: str = "") -> list[str]:
    return script.exports_sync.java_enumerate(filter)
