import json
from pare_frida_mcp.capture.store import CaptureStore
from pare_frida_mcp.capture.search import search_capture

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


def test_open_memory_is_usable_and_searchable():
    store = CaptureStore.open_memory()
    seq = store.write({"type": "snapshot", "source": "enum:dev=A",
                       "payload": {"pid": 1, "name": "initd"}, "summary": "initd"})
    assert seq == 1
    assert store.get(seq)["source"] == "enum:dev=A"
    # FTS works in-memory:
    res = search_capture(store, text="initd")
    assert res["total"] == 1
    store.close()


def test_delete_by_source_removes_rows_and_fts_entries():
    store = CaptureStore.open_memory()
    store.write({"type": "snapshot", "source": "enum:dev=A",
                 "payload": {"pid": 1, "name": "alpha"}, "summary": "alpha"})
    store.write({"type": "snapshot", "source": "enum:dev=A",
                 "payload": {"pid": 2, "name": "beta"}, "summary": "beta"})
    store.write({"type": "snapshot", "source": "enum:dev=B",
                 "payload": {"pid": 3, "name": "gamma"}, "summary": "gamma"})

    removed = store.delete_by_source("enum:dev=A")
    assert removed == 2

    # Rows for the source are gone...
    assert search_capture(store, field="source", contains="enum:dev=A")["total"] == 0
    # ...and the FTS index no longer matches them (guards the orphaned-index bug).
    assert search_capture(store, text="alpha")["total"] == 0
    assert search_capture(store, text="beta")["total"] == 0
    # The other source is untouched.
    assert search_capture(store, text="gamma")["total"] == 1
    store.close()
