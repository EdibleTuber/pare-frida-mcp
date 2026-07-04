from __future__ import annotations

from collections import deque
from typing import Any

from pare_frida_mcp.config import Config
from pare_frida_mcp.ids import new_session_id


class Session:
    def __init__(self, session_id: str, script: Any, pid: int, name: str,
                 queue_bound: int, device_id: str | None = None):
        self.id = session_id
        self.script = script
        self.pid = pid
        self.name = name
        self.device_id = device_id
        self._queue: deque[dict] = deque()
        self._queue_bound = queue_bound
        self.dropped = 0
        self.frida_session = None
        script.on("message", self._on_message)

    def _on_message(self, message: dict, data: Any) -> None:
        if len(self._queue) >= self._queue_bound:
            self.dropped += 1
            return
        self._queue.append(message)

    def flush(self) -> None:
        self._queue.clear()


class SessionManager:
    def __init__(self, config: Config, queue_bound: int = 10000):
        self._config = config
        self._queue_bound = queue_bound
        self._sessions: dict[str, Session] = {}

    def register_session(self, *, script: Any, pid: int, name: str,
                         device_id: str | None = None) -> str:
        sid = new_session_id()
        self._sessions[sid] = Session(sid, script, pid, name, self._queue_bound,
                                      device_id)
        return sid

    def get(self, session_id: str) -> Session:
        return self._sessions[session_id]

    def find_live_session(self, pid: int, device_id: str | None = None) -> str | None:
        """Return the id of a LIVE session for this (device, pid), or None.

        Dedupe key is (device_id, pid): a pid is only unique within a device.
        Liveness uses the same frida.Session.is_detached probe as list_sessions;
        a dead session never matches, so a fresh attach replaces it."""
        for s in self._sessions.values():
            if s.pid != pid or s.device_id != device_id:
                continue
            fs = s.frida_session
            detached = True if fs is None else bool(getattr(fs, "is_detached", True))
            if not detached:
                return s.id
        return None

    def list_sessions(self) -> list[dict]:
        """Snapshot of live sessions with a real per-session liveness probe.

        Liveness reads frida.Session.is_detached - a cheap property, no RPC to
        the target. A missing frida_session, or a session object lacking
        is_detached, is treated as NOT live: we must never report a dead
        session as alive.
        """
        rows = []
        for s in self._sessions.values():
            fs = s.frida_session
            detached = True if fs is None else bool(getattr(fs, "is_detached", True))
            rows.append({"session_id": s.id, "pid": s.pid,
                         "name": s.name, "live": not detached})
        return rows

    def detach(self, session_id: str) -> None:
        """Detach the live session.

        Raises KeyError if session_id is unknown. If the underlying
        frida.Session is already dead (USB drop), the detach() call may throw -
        we swallow it and tear down our own state regardless.
        """
        s = self._sessions.pop(session_id)  # KeyError if absent - handler maps to _err
        fs = s.frida_session
        if fs is not None:
            try:
                fs.detach()
            except Exception:
                pass
        s.flush()

    def flush(self, session_id: str) -> None:
        self._sessions[session_id].flush()

    def dropped_count(self, session_id: str) -> int:
        return self._sessions[session_id].dropped

    def close_all(self) -> None:
        for s in self._sessions.values():
            s.flush()
        self._sessions.clear()
