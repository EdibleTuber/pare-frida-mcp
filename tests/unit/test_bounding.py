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
