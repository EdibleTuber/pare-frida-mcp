import pytest
from pare_frida_mcp.capture.store import CaptureStore
from pare_frida_mcp.capture.page import page_rows, list_sources


def _seed(store, source, items, summary_field="name"):
    for it in items:
        store.write({"type": "snapshot", "source": source,
                     "summary": str(it.get(summary_field, "")), "payload": it})


def test_page_rows_returns_all_items_in_order():
    store = CaptureStore.open_memory()
    _seed(store, "s1", [{"name": "c"}, {"name": "a"}, {"name": "b"}])
    res = page_rows(store, source="s1")
    assert res["total"] == 3
    assert res["shown"] == 3
    assert [r["name"] for r in res["rows"]] == ["c", "a", "b"]   # seq order, unsampled


def test_page_rows_filters_on_summary_like():
    store = CaptureStore.open_memory()
    _seed(store, "apps", [{"identifier": "com.bank"}, {"identifier": "com.maps"}],
          summary_field="identifier")
    res = page_rows(store, source="apps", field="summary", contains="bank")
    assert res["total"] == 1
    assert res["rows"][0]["identifier"] == "com.bank"


def test_page_rows_rejects_unallowed_field():
    store = CaptureStore.open_memory()
    _seed(store, "s1", [{"name": "a"}])
    with pytest.raises(ValueError):
        page_rows(store, source="s1", field="payload", contains="a")


def test_page_rows_byte_honest_cap_reports_shown_vs_total():
    store = CaptureStore.open_memory()
    _seed(store, "big", [{"name": f"item-{i}", "blob": "x" * 200} for i in range(50)])
    res = page_rows(store, source="big", byte_budget=2048)   # forces a partial page
    assert res["total"] == 50
    assert 0 < res["shown"] < 50              # whole rows only, honest count
    assert all("name" in r for r in res["rows"])


def test_list_sources_catalog():
    store = CaptureStore.open_memory()
    _seed(store, "a", [{"name": "1"}, {"name": "2"}])
    _seed(store, "b", [{"name": "3"}])
    cat = list_sources(store)
    assert {"source": "a", "count": 2} in cat
    assert {"source": "b", "count": 1} in cat
