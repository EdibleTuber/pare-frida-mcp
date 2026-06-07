from __future__ import annotations

from collections import OrderedDict
from urllib.parse import quote

from pare_frida_mcp.capture.store import CaptureStore

SNAPSHOT_HANDLE = "@snapshots"  # reserved; not a valid session id


def snapshot_key(tool: str, **kwargs) -> str:
    """Stable per-query key: tool plus sorted non-empty args.

    Segments are percent-encoded so a value containing ':' or '=' (e.g. a
    filter string) can't produce a key that collides with a different query.
    """
    parts = [quote(tool, safe="")]
    for k, v in sorted(kwargs.items()):
        if v in ("", None):
            continue
        parts.append(f"{quote(k, safe='')}={quote(str(v), safe='')}")
    return ":".join(parts)


class SnapshotStore:
    """Sessionless, in-memory store of latest-per-query device snapshots.

    Replace semantics: re-running a query (same key) upserts that key's rows.
    An LRU bound on distinct keys keeps a long session from growing unbounded;
    the default of 32 distinct queries is roughly a few hundred rows — tune
    upward if a workflow holds many snapshots at once.
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

    def latest_source(self) -> str | None:
        """The most-recently-replaced source key (MRU), or None if empty.

        Uses the LRU OrderedDict (insertion/touch order) rather than MAX(seq):
        seq is a reused SQLite rowid, so a replaced source can take lower seqs
        and 'highest seq' would point at the wrong snapshot.
        """
        if not self._keys:
            return None
        return next(reversed(self._keys))
