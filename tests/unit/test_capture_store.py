import json
from pare_frida_mcp.capture.store import CaptureStore

def test_write_and_promote(tmp_path):
    store = CaptureStore.open(tmp_path, "sess", blob_threshold=65536)
    seq = store.write({
        "type": "send",
        "source": "hook1",
        "payload": {"method": "doLogin", "url": "https://x/login", "class": "Auth"},
        "summary": "doLogin called",
    })
    assert seq == 1
    row = store.get(seq)
    assert row["method"] == "doLogin"
    assert row["url"] == "https://x/login"
    assert row["cls"] == "Auth"
    assert json.loads(row["payload"])["method"] == "doLogin"
    store.close()

def test_blob_spill(tmp_path):
    store = CaptureStore.open(tmp_path, "sess", blob_threshold=16)
    big = "Z" * 1000
    seq = store.write({"type": "send", "source": "dump", "payload": {"data": big}, "summary": "dump"})
    row = store.get(seq)
    assert row["blob_ref"] is not None
    assert (tmp_path / "sess" / "blobs" / f"{seq}.bin").exists()
    store.close()
