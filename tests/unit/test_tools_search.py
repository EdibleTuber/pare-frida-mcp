import json
import pytest

from pare_frida_mcp import tools as T
from pare_frida_mcp.core.snapshots import SNAPSHOT_HANDLE


@pytest.mark.asyncio
async def test_search_count_only_returns_total_no_rows():
    T.SNAPSHOTS.replace("enum:dev=A",
                        [{"pid": i, "name": f"p{i}"} for i in range(40)])
    res = json.loads(await T.search_capture(SNAPSHOT_HANDLE, field="source",
                                            contains="enum:dev=A", count_only=True))
    assert res["total"] == 40
    assert res.get("count_only") is True
    assert "matches" not in res
    assert "count only" in res["summary"]


@pytest.mark.asyncio
async def test_search_limit_peek_summary_mentions_sample():
    T.SNAPSHOTS.replace("enum:dev=A",
                        [{"pid": i, "name": f"p{i}"} for i in range(40)])
    res = json.loads(await T.search_capture(SNAPSHOT_HANDLE, field="source",
                                            contains="enum:dev=A", limit=2))
    assert res["total"] == 40
    assert res["returned"] == 2
    assert "spread sample" in res["summary"]
    assert "read_capture" in res["summary"]


@pytest.mark.asyncio
async def test_search_large_result_is_valid_json_and_truncated():
    # Reproduces the emulator failure: a broad search over a big snapshot.
    T.SNAPSHOTS.replace("enum:dev=A",
                        [{"pid": i, "name": "x" * 60} for i in range(200)])
    raw = await T.search_capture(SNAPSHOT_HANDLE, field="source", contains="enum:dev=A")
    res = json.loads(raw)             # MUST NOT raise (the bug we are fixing)
    assert res["total"] == 200
    assert res["truncated"] is True
    assert isinstance(res["matches"], list)


@pytest.mark.asyncio
async def test_search_exact_small_result_untruncated():
    T.SNAPSHOTS.replace("enum:dev=A", [{"pid": 1, "name": "solo"}])
    res = json.loads(await T.search_capture(SNAPSHOT_HANDLE, field="source",
                                            contains="enum:dev=A"))
    assert res["total"] == 1
    assert res["truncated"] is False
    assert res["summary"] == "1 matches"
