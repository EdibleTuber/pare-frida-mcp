from pare_frida_mcp.capture.store import CaptureStore
from pare_frida_mcp.capture.read import read_capture


def test_read_by_seq_bounded(tmp_path):
    store = CaptureStore.open(tmp_path, "s", blob_threshold=65536)
    seq = store.write({"type": "send", "source": "h", "summary": "x",
                       "payload": {"big": "Q" * 10000}})
    res = read_capture(store, seq=seq, byte_budget=256)
    assert res["truncated"] is True
    assert len(res["text"].encode("utf-8")) <= 256
    store.close()
