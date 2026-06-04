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
from pare_frida_mcp.bounding import fit_items


def test_fit_all_when_under_budget():
    items = [{"pid": i, "name": f"p{i}"} for i in range(5)]
    fitted, fully = fit_items(items, byte_budget=4096)
    assert fitted == items
    assert fully is True


def test_fit_drops_whole_items_and_stays_valid_json():
    items = [{"pid": i, "name": "x" * 80} for i in range(500)]
    fitted, fully = fit_items(items, byte_budget=4096)
    assert fully is False
    assert 0 < len(fitted) < 500
    json.loads(json.dumps({"matches": fitted}))  # must round-trip


def test_fit_returns_at_least_one_item():
    items = [{"blob": "z" * 9000}, {"pid": 2}]
    fitted, fully = fit_items(items, byte_budget=4096)
    assert len(fitted) == 1          # forward progress guaranteed
    assert fully is False


def test_fit_empty_is_fully_fit():
    fitted, fully = fit_items([], byte_budget=4096)
    assert fitted == []
    assert fully is True
