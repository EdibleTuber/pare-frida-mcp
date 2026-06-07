import json
import pytest
from pare_frida_mcp import tools as T


@pytest.mark.asyncio
async def test_page_capture_returns_complete_rows_for_latest():
    T.SNAPSHOTS.replace("enumerate_applications:device=emu",
                        [{"identifier": "com.bank"}, {"identifier": "com.maps"}],
                        summary_field="identifier")
    out = json.loads(await T.page_capture("@snapshots"))   # source omitted -> latest
    assert out["store"] == "@snapshots"
    assert out["source"] == "enumerate_applications:device=emu"
    assert out["total"] == 2
    assert {r["identifier"] for r in out["rows"]} == {"com.bank", "com.maps"}


@pytest.mark.asyncio
async def test_page_capture_filters_by_summary():
    T.SNAPSHOTS.replace("apps:1", [{"identifier": "com.bank"}, {"identifier": "com.maps"}],
                        summary_field="identifier")
    out = json.loads(await T.page_capture("@snapshots", source="apps:1",
                                          field="summary", contains="bank"))
    assert out["total"] == 1
    assert out["rows"][0]["identifier"] == "com.bank"


@pytest.mark.asyncio
async def test_page_capture_list_sources():
    T.SNAPSHOTS.replace("k1", [{"name": "a"}])
    out = json.loads(await T.page_capture("@snapshots", list_sources=True))
    assert any(s["source"] == "k1" for s in out["sources"])


@pytest.mark.asyncio
async def test_page_capture_empty_store_is_graceful(monkeypatch):
    monkeypatch.setattr(T, "SNAPSHOTS", type(T.SNAPSHOTS)())   # fresh empty store
    out = json.loads(await T.page_capture("@snapshots"))
    assert out.get("total", 0) == 0 or "sources" in out


@pytest.mark.asyncio
async def test_enumerate_summary_advertises_snapshot(monkeypatch):
    from pare_frida_mcp.core import devices as devices_mod
    monkeypatch.setattr(devices_mod, "get_device", lambda _id=None: type("D", (), {"id": "emu", "type": "usb"})())
    monkeypatch.setattr(devices_mod, "enumerate_processes", lambda d: [{"pid": 1, "name": "init"}])
    out = json.loads(await T.enumerate_processes("emu"))
    assert "/snapshot" in out["summary"]
