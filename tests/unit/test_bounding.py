from pare_frida_mcp.bounding import bound_text


def test_short_text_untouched():
    text, truncated = bound_text("hello", 4096)
    assert text == "hello" and truncated is False


def test_truncates_on_byte_cap():
    text, truncated = bound_text("a" * 5000, 4096)
    assert truncated is True
    assert len(text.encode("utf-8")) <= 4096


def test_never_splits_codepoint():
    # 'é' is 2 bytes in UTF-8; cap mid-codepoint must back off cleanly.
    text, truncated = bound_text("é" * 100, 5)
    assert truncated is True
    text.encode("utf-8")  # must not raise; must be valid UTF-8


import json
from pare_frida_mcp.bounding import page_items


def _items(n):
    return [{"pid": i, "name": f"proc-{i}"} for i in range(n)]


def test_page_fits_returns_all_untruncated():
    page, nxt, truncated = page_items(_items(5), offset=0, limit=0, byte_budget=4096)
    assert len(page) == 5
    assert truncated is False
    assert nxt is None


def test_page_overflow_truncates_at_item_level_and_stays_valid_json():
    items = [{"pid": i, "name": "x" * 80} for i in range(500)]
    page, nxt, truncated = page_items(items, offset=0, limit=0, byte_budget=4096)
    assert truncated is True
    assert 0 < len(page) < 500
    # The whole envelope must serialize and re-parse cleanly.
    json.loads(json.dumps({"processes": page}))
    assert nxt == len(page)


def test_paging_with_offset_walks_without_gap_or_overlap():
    items = [{"pid": i, "name": "x" * 80} for i in range(500)]
    seen, offset, guard = [], 0, 0
    while offset is not None:
        page, offset, _ = page_items(items, offset=offset, limit=0, byte_budget=4096)
        seen.extend(p["pid"] for p in page)
        guard += 1
        assert guard < 1000  # forward-progress guard
    assert seen == list(range(500))


def test_explicit_limit_caps_count():
    page, nxt, truncated = page_items(_items(100), offset=0, limit=10, byte_budget=4096)
    assert len(page) == 10
    assert truncated is True
    assert nxt == 10


def test_single_oversized_item_still_advances():
    items = [{"pid": 0, "name": "z" * 9000}, {"pid": 1, "name": "ok"}]
    page, nxt, truncated = page_items(items, offset=0, limit=0, byte_budget=4096)
    assert len(page) == 1  # at least one item to guarantee progress
    assert nxt == 1
    assert truncated is True
