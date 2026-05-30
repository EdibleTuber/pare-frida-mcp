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


def test_spilled_payload_is_nulled_and_restored_by_read(tmp_path):
    # blob_threshold tiny so this payload definitely spills.
    store = CaptureStore.open(tmp_path, "s", blob_threshold=16)
    seq = store.write({"type": "send", "source": "x", "summary": "big",
                       "payload": {"data": "Q" * 1000}})
    # The row's payload column is NULL after spill (kept the row small),
    # and the blob_ref points at the spilled file.
    row = store.get(seq)
    assert row["payload"] is None
    assert row["blob_ref"] is not None
    # read_capture must transparently restore the payload from the blob so
    # callers don't have to know about the spill happened.
    res = read_capture(store, seq=seq, byte_budget=8192)
    assert res["truncated"] is False
    assert "Q" * 1000 in res["text"]
    store.close()
