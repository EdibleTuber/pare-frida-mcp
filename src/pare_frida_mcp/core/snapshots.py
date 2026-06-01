from __future__ import annotations

from collections import OrderedDict

from pare_frida_mcp.capture.store import CaptureStore

SNAPSHOT_HANDLE = "@snapshots"  # reserved; not a valid session id


def snapshot_key(tool: str, **args) -> str:
    """Stable per-query key: tool plus sorted non-empty args."""
    parts = [tool] + [f"{k}={v}" for k, v in sorted(args.items()) if v not in ("", None)]
    return ":".join(parts)


class SnapshotStore:
    """Sessionless, in-memory store of latest-per-query device snapshots.

    Replace semantics: re-running a query (same key) upserts that key's rows.
    An LRU bound on distinct keys keeps a long session from growing unbounded.
    """

    def __init__(self, max_keys: int = 32):
        self.store = CaptureStore.open_memory()
        self._keys: "OrderedDict[str, None]" = OrderedDict()
        self._max_keys = max_keys

    def replace(self, source: str, items: list[dict], summary_field: str = "name") -> int:
        self.store.delete_by_source(source)
        for item in items:
            self.store.write({
                "type": "snapshot",
                "source": source,
                "summary": str(item.get(summary_field, "")),
                "payload": item,
            })
        self._keys.pop(source, None)
        self._keys[source] = None  # mark most-recently-used
        while len(self._keys) > self._max_keys:
            old, _ = self._keys.popitem(last=False)
            self.store.delete_by_source(old)
        return len(items)
