import json
from pare_frida_mcp.tools import _ok


def test_ok_returns_full_payload_over_old_cap():
    big = "ab" * 5000  # ~10KB, far over the old 4096 cap
    out = _ok("read complete", hex=big)
    doc = json.loads(out)
    assert doc["hex"] == big              # not truncated
    assert "capture" not in doc            # no handle key
