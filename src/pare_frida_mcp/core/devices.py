from __future__ import annotations
import frida

def enumerate_devices() -> list[dict]:
    return [{"id": d.id, "name": d.name, "type": d.type} for d in frida.enumerate_devices()]

def get_device(device_id: str | None):
    if device_id:
        return frida.get_device(device_id, timeout=2)
    return frida.get_usb_device(timeout=2)
