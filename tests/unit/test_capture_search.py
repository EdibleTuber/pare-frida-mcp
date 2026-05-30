from pare_frida_mcp.capture.store import CaptureStore
from pare_frida_mcp.capture.search import search_capture

def _seed(tmp_path):
    store = CaptureStore.open(tmp_path, "s", blob_threshold=65536)
    store.write({"type": "send", "source": "h", "summary": "login",
                 "payload": {"url": "https://x/login", "method": "POST"}})
    store.write({"type": "send", "source": "h", "summary": "fetch",
                 "payload": {"url": "https://x/data", "method": "GET"}})
    return store

def test_field_predicate_uses_column(tmp_path):
    store = _seed(tmp_path)
    res = search_capture(store, field="url", contains="login", byte_budget=4096)
    assert res["total"] == 1
    assert res["matches"][0]["method"] == "POST"
    store.close()

def test_fts_text_search(tmp_path):
    store = _seed(tmp_path)
    res = search_capture(store, text="fetch", byte_budget=4096)
    assert res["total"] == 1
    store.close()
