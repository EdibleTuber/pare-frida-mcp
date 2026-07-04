import json

from pare_frida_mcp import tools as T


def test_ok_normal_payload_is_unchanged():
    out = T._ok("hi", n=1, items=[1, 2, 3])
    assert json.loads(out) == {"summary": "hi", "n": 1, "items": [1, 2, 3]}


def test_ok_oversized_payload_returns_full_json():
    # Cap removed: _ok now returns the full envelope unconditionally.
    huge = {"rows": [{"x": "y" * 100} for _ in range(1000)]}  # far exceeds old _CAP
    out = T._ok("done", **huge)
    res = json.loads(out)               # MUST NOT raise
    assert res["rows"] == huge["rows"]  # full payload present
    assert "truncated" not in res       # no fallback envelope


def test_err_normal_payload_is_unchanged():
    out = T._err("boom", ValueError("bad"))
    res = json.loads(out)
    assert res["error"] is True
    assert res["detail"] == "bad"       # str(exc); no type prefix in new _err


def test_err_oversized_detail_returns_full_json():
    # Cap removed: _err now returns the full detail unconditionally.
    long_msg = "z" * 20000
    out = T._err("boom", RuntimeError(long_msg))
    res = json.loads(out)               # MUST NOT raise
    assert res["error"] is True
    assert res["detail"] == long_msg    # full detail present
