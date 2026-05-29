from __future__ import annotations

from collections import deque
from typing import Any

from pare_frida_mcp.config import Config
from pare_frida_mcp.capture.store import CaptureStore
from pare_frida_mcp.ids import new_session_id


class Session:
    def __init__(self, session_id: str, script: Any, pid: int, name: str,
                 store: CaptureStore, queue_bound: int):
        self.id = session_id
        self.script = script
        self.pid = pid
        self.name = name
        self.store = store
        self._queue: deque[dict] = deque()
        self._queue_bound = queue_bound
        self.dropped = 0
        script.on("message", self._on_message)

    def _on_message(self, message: dict, data: Any) -> None:
        if len(self._queue) >= self._queue_bound:
            self.dropped += 1
            return
        self._queue.append(message)

    def flush(self) -> None:
        while self._queue:
            self.store.write(self._queue.popleft())


class SessionManager:
    def __init__(self, config: Config, queue_bound: int = 10000):
        self._config = config
        self._queue_bound = queue_bound
        self._sessions: dict[str, Session] = {}

    def register_session(self, *, script: Any, pid: int, name: str) -> str:
        sid = new_session_id()
        store = CaptureStore.open(self._config.capture_dir, sid,
                                  self._config.blob_threshold)
        self._sessions[sid] = Session(sid, script, pid, name, store, self._queue_bound)
        return sid

    def flush(self, session_id: str) -> None:
        self._sessions[session_id].flush()

    def store_for(self, session_id: str) -> CaptureStore:
        return self._sessions[session_id].store

    def dropped_count(self, session_id: str) -> int:
        return self._sessions[session_id].dropped

    def close_all(self) -> None:
        for s in self._sessions.values():
            s.flush()
            s.store.close()
        self._sessions.clear()
