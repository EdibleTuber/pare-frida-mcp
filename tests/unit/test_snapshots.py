from pare_frida_mcp.core.snapshots import SnapshotStore, snapshot_key, SNAPSHOT_HANDLE
from pare_frida_mcp.capture.search import search_capture


def test_snapshot_key_is_stable_and_drops_empty_args():
    k = snapshot_key("enumerate_processes", device_id="emulator-5554", filter="")
    assert k == "enumerate_processes:device_id=emulator-5554"
    # order-independent
    assert snapshot_key("t", b="2", a="1") == snapshot_key("t", a="1", b="2")


def test_handle_constant():
    assert SNAPSHOT_HANDLE == "@snapshots"
    assert SNAPSHOT_HANDLE.startswith("@")  # cannot be mistaken for a session id


def test_replace_is_upsert_per_key():
    snaps = SnapshotStore()
    key = "enumerate_processes:device_id=A"
    snaps.replace(key, [{"pid": 1, "name": "old1"}, {"pid": 2, "name": "old2"}])
    snaps.replace(key, [{"pid": 9, "name": "fresh"}])  # re-run replaces
    assert search_capture(snaps.store, field="source", contains=key)["total"] == 1
    assert search_capture(snaps.store, text="old1")["total"] == 0
    assert search_capture(snaps.store, text="fresh")["total"] == 1


def test_distinct_keys_coexist():
    snaps = SnapshotStore()
    snaps.replace("enumerate_processes:device_id=A", [{"pid": 1, "name": "aaa"}])
    snaps.replace("enumerate_processes:device_id=B", [{"pid": 1, "name": "bbb"}])
    assert search_capture(snaps.store, text="aaa")["total"] == 1
    assert search_capture(snaps.store, text="bbb")["total"] == 1


def test_lru_evicts_oldest_key():
    snaps = SnapshotStore(max_keys=2)
    snaps.replace("k1", [{"pid": 1, "name": "one"}])
    snaps.replace("k2", [{"pid": 2, "name": "two"}])
    snaps.replace("k3", [{"pid": 3, "name": "three"}])  # evicts k1
    assert search_capture(snaps.store, text="one")["total"] == 0
    assert search_capture(snaps.store, text="two")["total"] == 1
    assert search_capture(snaps.store, text="three")["total"] == 1


def test_snapshot_key_no_kwargs():
    assert snapshot_key("list_devices") == "list_devices"


def test_snapshot_key_encodes_separators_in_values():
    # A value containing ':'/'=' must not collide with a different query.
    assert snapshot_key("t", a="1:b=2") != snapshot_key("t", a="1", b="2")


def test_replace_with_empty_items_clears_stale():
    snaps = SnapshotStore()
    key = "enumerate_processes:device_id=A"
    snaps.replace(key, [{"pid": 1, "name": "stale"}])
    assert snaps.replace(key, []) == 0
    assert search_capture(snaps.store, text="stale")["total"] == 0


def test_re_replace_promotes_key_to_mru():
    snaps = SnapshotStore(max_keys=2)
    snaps.replace("k1", [{"pid": 1, "name": "one"}])
    snaps.replace("k2", [{"pid": 2, "name": "two"}])
    snaps.replace("k1", [{"pid": 1, "name": "one2"}])   # touch k1 -> most-recently-used
    snaps.replace("k3", [{"pid": 3, "name": "three"}])  # should evict k2, not k1
    assert search_capture(snaps.store, text="one2")["total"] == 1   # k1 survived
    assert search_capture(snaps.store, text="two")["total"] == 0    # k2 evicted
    assert search_capture(snaps.store, text="three")["total"] == 1


def test_latest_source_is_most_recently_replaced():
    s = SnapshotStore()
    assert s.latest_source() is None          # empty store
    s.replace("alpha", [{"name": "a"}])
    s.replace("beta", [{"name": "b"}])
    assert s.latest_source() == "beta"        # MRU, not seq order
    s.replace("alpha", [{"name": "a2"}])      # touch alpha -> now MRU
    assert s.latest_source() == "alpha"
