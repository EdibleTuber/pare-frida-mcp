from __future__ import annotations

import re
import uuid

_SESSION_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


def new_session_id() -> str:
    return str(uuid.uuid4())


def validate_session_id(session_id: str) -> str:
    if not isinstance(session_id, str) or not _SESSION_RE.match(session_id):
        raise ValueError(f"invalid session_id: {session_id!r}")
    return session_id
