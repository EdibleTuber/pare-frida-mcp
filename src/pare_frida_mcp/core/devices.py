from __future__ import annotations
import frida

def enumerate_devices() -> list[dict]:
    return [{"id": d.id, "name": d.name, "type": d.type} for d in frida.enumerate_devices()]

def get_device(device_id: str | None):
    if device_id:
        return frida.get_device(device_id, timeout=2)
    return frida.get_usb_device(timeout=2)


def enumerate_processes(device) -> list[dict]:
    procs = [{"pid": p.pid, "name": p.name} for p in device.enumerate_processes()]
    procs.sort(key=lambda p: (p["name"] or "").lower())
    return procs


def enumerate_applications(device) -> list[dict]:
    try:
        apps = device.enumerate_applications(scope="minimal")
    except TypeError:
        # Older/alternate frida builds may not accept the scope kwarg.
        apps = device.enumerate_applications()
    out = [{"identifier": a.identifier, "name": a.name, "pid": a.pid} for a in apps]
    out.sort(key=lambda a: (a["identifier"] or "").lower())
    return out
