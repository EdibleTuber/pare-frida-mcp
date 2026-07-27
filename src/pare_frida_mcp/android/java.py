from __future__ import annotations


def java_hook(script, cls: str, method: str, overload: list | None = None,
              capture_this: list | None = None) -> dict:
    return script.exports_sync.java_hook_install(
        cls, method, overload or [], capture_this or [])


def java_read_fields(script, cls: str, fields: list | None = None) -> dict:
    return script.exports_sync.java_read_fields(cls, fields or [])


def enumerate_classes(script, filter: str = "") -> list[str]:
    return script.exports_sync.java_enumerate(filter)


def enumerate_methods(script, cls: str) -> list[dict]:
    return script.exports_sync.java_enumerate_methods(cls)
