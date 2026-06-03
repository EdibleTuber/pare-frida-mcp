import json
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


def _seed_n(n, name_len=8):
    store = CaptureStore.open_memory()
    for i in range(n):
        store.write({"type": "snapshot", "source": "enum:dev=A",
                     "summary": f"proc{i:04d}",
                     "payload": {"pid": i, "name": "n" * name_len}})
    return store


def test_lean_rows_drop_null_columns():
    store = _seed_n(1)
    res = search_capture(store, field="source", contains="enum:dev=A", byte_budget=4096)
    row = res["matches"][0]
    for absent in ("hook", "url", "method", "cls", "ret", "blob_ref"):
        assert absent not in row, row
    for present in ("seq", "source", "summary", "payload"):
        assert present in row, row
    store.close()


def test_count_only_returns_total_without_rows():
    store = _seed_n(40)
    res = search_capture(store, field="source", contains="enum:dev=A", count_only=True)
    assert res["total"] == 40
    assert "matches" not in res
    store.close()


def test_limit_peek_returns_few_rows_with_true_total():
    store = _seed_n(40)
    res = search_capture(store, field="source", contains="enum:dev=A", limit=2)
    assert res["total"] == 40
    assert res["returned"] == 2
    assert res["truncated"] is True
    assert res["sampled"] is True
    store.close()


def test_spread_sampling_is_distributed_not_first_n():
    store = _seed_n(100)
    res = search_capture(store, field="source", contains="enum:dev=A", limit=5)
    assert res["total"] == 100
    assert res["returned"] == 5
    assert res["sampled"] is True
    seqs = [m["seq"] for m in res["matches"]]
    assert seqs == sorted(seqs)
    assert seqs[0] == 1 and seqs[-1] == 100
    assert (seqs[-1] - seqs[0]) > 5
    store.close()


def test_small_set_returns_all_in_order_untruncated():
    store = _seed_n(3)
    res = search_capture(store, field="source", contains="enum:dev=A", limit=50)
    assert res["total"] == 3
    assert res["returned"] == 3
    assert res["truncated"] is False
    assert res["sampled"] is False
    store.close()


def test_over_budget_result_is_valid_and_marks_truncated():
    store = _seed_n(200, name_len=200)
    res = search_capture(store, field="source", contains="enum:dev=A", byte_budget=4096)
    assert res["total"] == 200
    assert res["returned"] < 200
    assert res["truncated"] is True
    json.loads(json.dumps({"matches": res["matches"]}))
    store.close()


def test_single_oversized_payload_is_clipped_not_corrupting():
    store = CaptureStore.open_memory()
    store.write({"type": "snapshot", "source": "big", "summary": "huge",
                 "payload": {"data": "Q" * 9000}})
    res = search_capture(store, field="source", contains="big", byte_budget=4096)
    assert res["returned"] == 1
    assert res["truncated"] is True
    json.loads(json.dumps(res["matches"]))
    assert len(res["matches"][0]["payload"].encode("utf-8")) <= 4096
    store.close()
