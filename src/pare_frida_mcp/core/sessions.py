from __future__ import annotations

import json
from collections import deque
from dataclasses import dataclass
from typing import Any

from pare_frida_mcp.config import Config
from pare_frida_mcp.ids import new_session_id

_DIAGNOSTIC_BOUND = 256


@dataclass
class ReadResult:
    events: list[dict]
    next_seq: int
    buffered_remaining: int
    has_more: bool
    lost: int


class Session:
    def __init__(self, session_id: str, script: Any, pid: int, name: str,
                 event_bound: int, device_id: str | None = None):
        self.id = session_id
        self.script = script
        self.pid = pid
        self.name = name
        self.device_id = device_id
        self._events: deque[dict] = deque(maxlen=event_bound)          # hook events, seq-ascending
        self._diagnostics: deque[dict] = deque(maxlen=_DIAGNOSTIC_BOUND)  # frida errors/logs/non-hook
        self.frida_session = None
        script.on("message", self._on_message)

    def _on_message(self, message: dict, data: Any) -> None:
        if message.get("type") == "send":
            payload = message.get("payload")
            if isinstance(payload, dict) and payload.get("hook"):
                self._events.append(payload)
                return
        self._diagnostics.append(message)

    def flush(self) -> None:
        self._events.clear()
        self._diagnostics.clear()


class SessionManager:
    def __init__(self, config: Config, event_bound: int = 2048):
        # event_bound sized for enriched events (each up to ~CAP bytes hex + utf8);
        # worst-case resident memory ~= event_bound * per-event-max. NOT the old
        # 10000 thin-message default.
        self._config = config
        self._event_bound = event_bound
        self._sessions: dict[str, Session] = {}

    def register_session(self, *, script: Any, pid: int, name: str,
                         device_id: str | None = None) -> str:
        sid = new_session_id()
        self._sessions[sid] = Session(sid, script, pid, name, self._event_bound,
                                      device_id)
        return sid

    def get(self, session_id: str) -> Session:
        return self._sessions[session_id]

    def active_session(self) -> str | None:
        """Id of the most-recent LIVE session, or None.

        Lets session-scoped tools default an omitted session_id to "the session
        I just attached", so the operator/model never has to restate it. Uses the
        same is_detached liveness probe as list_sessions; dead sessions are
        skipped even if more recent. _sessions preserves insertion order, so the
        last-registered live session wins.
        """
        for sid in reversed(self._sessions):
            fs = self._sessions[sid].frida_session
            detached = True if fs is None else bool(getattr(fs, "is_detached", True))
            if not detached:
                return sid
        return None

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

    def read_events(self, session_id: str, since_seq: int, limit: int,
                    max_bytes: int) -> ReadResult:
        """Non-destructive cursor read of hook events with seq > since_seq.

        Idempotent: reading never evicts. Stops at whichever bound (limit or
        max_bytes) is hit first, always returning at least one event when any
        qualify. `lost` counts events evicted below the cursor (the ring moved
        past since_seq) - the only true-loss signal, derived here race-free.
        """
        buf = list(self._sessions[session_id]._events)   # seq-ascending
        lost = 0
        if buf and since_seq < buf[0]["seq"] - 1:
            lost = buf[0]["seq"] - 1 - since_seq
        candidates = [e for e in buf if e["seq"] > since_seq]
        selected: list[dict] = []
        size = 0
        for e in candidates:
            if len(selected) >= limit:
                break
            esize = len(json.dumps(e))
            if selected and size + esize > max_bytes:
                break
            selected.append(e)
            size += esize
        next_seq = selected[-1]["seq"] if selected else since_seq
        remaining = len(candidates) - len(selected)
        return ReadResult(events=selected, next_seq=next_seq,
                          buffered_remaining=remaining, has_more=remaining > 0,
                          lost=lost)

    def close_all(self) -> None:
        for s in self._sessions.values():
            s.flush()
        self._sessions.clear()
