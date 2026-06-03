import json

from pare_frida_mcp import tools as T


def test_ok_normal_payload_is_unchanged():
    out = T._ok("hi", n=1, items=[1, 2, 3])
    assert json.loads(out) == {"summary": "hi", "n": 1, "items": [1, 2, 3]}


def test_ok_oversized_payload_returns_valid_fallback_json():
    huge = {"rows": [{"x": "y" * 100} for _ in range(1000)]}  # far exceeds _CAP
    out = T._ok("done", **huge)
    res = json.loads(out)               # MUST NOT raise
    assert res["truncated"] is True
    assert "error" in res
    assert len(out.encode("utf-8")) <= T._CAP


def test_err_normal_payload_is_unchanged():
    out = T._err("boom", ValueError("bad"))
    res = json.loads(out)
    assert res["error"] is True
    assert "ValueError" in res["detail"]


def test_err_oversized_detail_returns_valid_json():
    out = T._err("boom", RuntimeError("z" * 20000))
    res = json.loads(out)               # MUST NOT raise
    assert res["error"] is True
    assert len(out.encode("utf-8")) <= T._CAP
