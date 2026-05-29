# pare-frida-mcp Android v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Android-only v1 slice of `pare-frida-mcp` — a Python/FastMCP stdio MCP worker giving PARE Frida 17 dynamic instrumentation, with a context-bounded SQLite capture store.

**Architecture:** A FastMCP server runs over stdio. Tool metadata (name, risk_tier, input/output schema, handler) is centralized in `contract.py`, which feeds both FastMCP registration and `agent_core`'s `assert_conformance` self-test. A `SessionManager` owns Frida sessions and runs a batched message pump into a per-session SQLite `CaptureStore`; every tool return is bounded to a byte cap, spilling large data to the store/blobs and handing back a capture handle. Heavy in-target logic lives in a `frida-compile`'d JS bundle exposing RPC exports; `execute_script` is the arbitrary-eval escape hatch.

**Tech Stack:** Python 3.12, `frida`, `mcp` (FastMCP), stdlib `sqlite3` (WAL + FTS5), hatchling, pytest + pytest-asyncio; bundled agent is TypeScript/JS built with `frida-compile`. Mirrors `apk_re_agents` layout/packaging (but stdio transport, not HTTP).

---

## File Structure

```
pare-frida-mcp/
  pyproject.toml                       hatchling build, console-script entry, pytest config
  src/pare_frida_mcp/
    __init__.py
    config.py                          Config dataclass + load_config() from env
    ids.py                             new_session_id(), validate_session_id()
    bounding.py                        bound_text() — UTF-8-safe byte cap
    contract.py                        ToolSpec, CONTRACT_VERSION, tool registry, WorkerContractAdapter
    capture/
      __init__.py
      store.py                         CaptureStore: schema, record shaping, hot-field promotion, blob spill
      search.py                        search_capture() over promoted columns + FTS5
      read.py                          read_capture() bounded slice
    core/
      __init__.py
      devices.py                       list_devices / select_device
      sessions.py                      SessionManager, Session, message pump
      scripts.py                       load_script / execute_script
      memory.py                        enumerate/read/scan/write memory
    android/
      __init__.py
      java.py                          java_hook
    tools.py                           handler functions wired to ToolSpecs (thin, bounded)
    server.py                          build_server() -> FastMCP; main()
    agent/
      package.json                     frida-compile devDep + build script
      tsconfig.json
      src/index.ts                     RPC exports: java_*, mem_*, modules/exports
      dist/agent.js                    compiled bundle (built by CI / make)
  tests/
    __init__.py
    conftest.py                        shared fixtures (tmp config, fake frida script)
    unit/
      test_config.py
      test_ids.py
      test_bounding.py
      test_capture_store.py
      test_capture_search.py
      test_capture_read.py
      test_contract.py
      test_sessions_pump.py
    integration/
      test_conformance.py              assert_conformance against the worker
      test_server_list_tools.py        FastMCP handshake + tool listing
      test_stdio_handshake.py          MCPClient(command=...) end-to-end (skips if agent_core absent)
    device/
      conftest.py                      skip-if-no-device fixture
      test_android_flows.py            attach/script/hook/memory/capture on real USB
  agent/                               (symlink target or same as src/.../agent)
  README.md
  Makefile                             `make agent` -> frida-compile; `make test`
```

---

## Task 1: Project scaffolding & packaging

**Files:**
- Create: `pyproject.toml`
- Create: `src/pare_frida_mcp/__init__.py`
- Create: `tests/__init__.py`, `tests/unit/__init__.py`, `tests/integration/__init__.py`

- [ ] **Step 1: Write `pyproject.toml`**

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "pare-frida-mcp"
version = "0.1.0"
description = "Frida dynamic-instrumentation MCP worker for PARE (Android v1)"
requires-python = ">=3.12"
dependencies = [
    "frida>=17",
    "mcp>=1.27.0",
]

[project.optional-dependencies]
dev = [
    "pytest",
    "pytest-asyncio",
]

[project.scripts]
pare-frida-mcp = "pare_frida_mcp.server:main"

[tool.hatch.build.targets.wheel]
packages = ["src/pare_frida_mcp"]

[tool.pytest.ini_options]
asyncio_mode = "auto"
testpaths = ["tests"]
```

- [ ] **Step 2: Create empty package + test `__init__.py` files**

Create `src/pare_frida_mcp/__init__.py` with:

```python
__version__ = "0.1.0"
```

Create empty `tests/__init__.py`, `tests/unit/__init__.py`, `tests/integration/__init__.py`.

- [ ] **Step 3: Verify install works**

Run: `pip install -e ".[dev]"`
Expected: installs cleanly; `pare-frida-mcp` console script is on PATH (it will fail at runtime until `server.main` exists — that's fine).

- [ ] **Step 4: Commit**

```bash
git add pyproject.toml src/pare_frida_mcp/__init__.py tests/
git commit -m "chore: scaffold pare-frida-mcp package"
```

---

## Task 2: Config module

**Files:**
- Create: `src/pare_frida_mcp/config.py`
- Test: `tests/unit/test_config.py`

- [ ] **Step 1: Write the failing test**

```python
import os
from pare_frida_mcp.config import Config, load_config

def test_defaults(monkeypatch, tmp_path):
    for k in ("PARE_FRIDA_CAPTURE_DIR", "PARE_FRIDA_MAX_TOOL_BYTES",
              "PARE_FRIDA_BLOB_THRESHOLD", "PARE_FRIDA_MAX_DISK_PER_SESSION"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("PARE_FRIDA_CAPTURE_DIR", str(tmp_path))
    cfg = load_config()
    assert cfg.capture_dir == tmp_path
    assert cfg.max_tool_bytes == 4096
    assert cfg.blob_threshold == 65536
    assert cfg.max_disk_per_session == 512 * 1024 * 1024

def test_env_overrides(monkeypatch, tmp_path):
    monkeypatch.setenv("PARE_FRIDA_CAPTURE_DIR", str(tmp_path))
    monkeypatch.setenv("PARE_FRIDA_MAX_TOOL_BYTES", "2048")
    cfg = load_config()
    assert cfg.max_tool_bytes == 2048
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_config.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'pare_frida_mcp.config'`

- [ ] **Step 3: Write minimal implementation**

```python
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Config:
    capture_dir: Path
    max_tool_bytes: int
    blob_threshold: int
    max_disk_per_session: int


def load_config() -> Config:
    return Config(
        capture_dir=Path(os.environ.get("PARE_FRIDA_CAPTURE_DIR", "/tmp/pare-frida")),
        max_tool_bytes=int(os.environ.get("PARE_FRIDA_MAX_TOOL_BYTES", 4096)),
        blob_threshold=int(os.environ.get("PARE_FRIDA_BLOB_THRESHOLD", 65536)),
        max_disk_per_session=int(
            os.environ.get("PARE_FRIDA_MAX_DISK_PER_SESSION", 512 * 1024 * 1024)
        ),
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/unit/test_config.py -v`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add src/pare_frida_mcp/config.py tests/unit/test_config.py
git commit -m "feat: env-driven config"
```

---

## Task 3: Session IDs (UUID + validation)

**Files:**
- Create: `src/pare_frida_mcp/ids.py`
- Test: `tests/unit/test_ids.py`

- [ ] **Step 1: Write the failing test**

```python
import pytest
from pare_frida_mcp.ids import new_session_id, validate_session_id

def test_new_id_is_uuid_shaped():
    sid = new_session_id()
    assert validate_session_id(sid) == sid

@pytest.mark.parametrize("bad", ["../../etc", "abc/def", "", "..", "a"*40, "X"*36])
def test_rejects_traversal_and_junk(bad):
    with pytest.raises(ValueError):
        validate_session_id(bad)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_ids.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write minimal implementation**

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/unit/test_ids.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/pare_frida_mcp/ids.py tests/unit/test_ids.py
git commit -m "feat: server-generated validated session ids"
```

---

## Task 4: Output bounding (UTF-8-safe byte cap)

**Files:**
- Create: `src/pare_frida_mcp/bounding.py`
- Test: `tests/unit/test_bounding.py`

- [ ] **Step 1: Write the failing test**

```python
from pare_frida_mcp.bounding import bound_text

def test_short_text_untouched():
    text, truncated = bound_text("hello", 4096)
    assert text == "hello" and truncated is False

def test_truncates_on_byte_cap():
    text, truncated = bound_text("a" * 5000, 4096)
    assert truncated is True
    assert len(text.encode("utf-8")) <= 4096

def test_never_splits_codepoint():
    # 'é' is 2 bytes in UTF-8; cap mid-codepoint must back off cleanly.
    text, truncated = bound_text("é" * 100, 5)
    assert truncated is True
    text.encode("utf-8")  # must not raise; must be valid UTF-8
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_bounding.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write minimal implementation**

```python
from __future__ import annotations


def bound_text(text: str, max_bytes: int) -> tuple[str, bool]:
    """Return (text, truncated). Truncates on a UTF-8 char boundary so the
    result is always valid UTF-8 and never exceeds max_bytes."""
    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return text, False
    clipped = encoded[:max_bytes]
    # Back off to the last complete codepoint.
    text_out = clipped.decode("utf-8", errors="ignore")
    return text_out, True
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/unit/test_bounding.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/pare_frida_mcp/bounding.py tests/unit/test_bounding.py
git commit -m "feat: UTF-8-safe output bounding"
```

---

## Task 5: Capture store — schema, record shaping, hot-field promotion

**Files:**
- Create: `src/pare_frida_mcp/capture/__init__.py` (empty)
- Create: `src/pare_frida_mcp/capture/store.py`
- Test: `tests/unit/test_capture_store.py`

- [ ] **Step 1: Write the failing test**

```python
import json
from pare_frida_mcp.capture.store import CaptureStore

def test_write_and_promote(tmp_path):
    store = CaptureStore.open(tmp_path, "sess", blob_threshold=65536)
    seq = store.write({
        "type": "send",
        "source": "hook1",
        "payload": {"method": "doLogin", "url": "https://x/login", "class": "Auth"},
        "summary": "doLogin called",
    })
    assert seq == 1
    row = store.get(seq)
    assert row["method"] == "doLogin"
    assert row["url"] == "https://x/login"
    assert row["cls"] == "Auth"
    assert json.loads(row["payload"])["method"] == "doLogin"
    store.close()

def test_blob_spill(tmp_path):
    store = CaptureStore.open(tmp_path, "sess", blob_threshold=16)
    big = "Z" * 1000
    seq = store.write({"type": "send", "source": "dump", "payload": {"data": big}, "summary": "dump"})
    row = store.get(seq)
    assert row["blob_ref"] is not None
    assert (tmp_path / "sess" / "blobs" / f"{seq}.bin").exists()
    store.close()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_capture_store.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write minimal implementation**

```python
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any

_SCHEMA = """
CREATE TABLE IF NOT EXISTS messages (
  seq INTEGER PRIMARY KEY,
  ts REAL NOT NULL,
  type TEXT NOT NULL,
  source TEXT,
  hook TEXT, url TEXT, method TEXT, cls TEXT, ret TEXT,
  summary TEXT, payload TEXT, blob_ref TEXT
);
CREATE INDEX IF NOT EXISTS idx_messages_ts ON messages(ts);
CREATE INDEX IF NOT EXISTS idx_messages_type ON messages(type);
CREATE INDEX IF NOT EXISTS idx_messages_source ON messages(source);
CREATE INDEX IF NOT EXISTS idx_messages_hook ON messages(hook);
CREATE INDEX IF NOT EXISTS idx_messages_url ON messages(url);
CREATE INDEX IF NOT EXISTS idx_messages_method ON messages(method);
CREATE INDEX IF NOT EXISTS idx_messages_cls ON messages(cls);
CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts
  USING fts5(summary, payload, content='messages', content_rowid='seq');
"""

_PROMOTE = {"hook": "hook", "url": "url", "method": "method", "class": "cls", "ret": "ret"}


class CaptureStore:
    def __init__(self, conn: sqlite3.Connection, session_dir: Path, blob_threshold: int):
        self._conn = conn
        self._dir = session_dir
        self._blob_threshold = blob_threshold

    @classmethod
    def open(cls, capture_dir: Path, session_id: str, blob_threshold: int) -> "CaptureStore":
        session_dir = Path(capture_dir) / session_id
        session_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        conn = sqlite3.connect(session_dir / "capture.db")
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(_SCHEMA)
        return cls(conn, session_dir, blob_threshold)

    def write(self, message: dict[str, Any]) -> int:
        payload = message.get("payload", {})
        payload_json = json.dumps(payload)
        promoted = {col: (payload.get(key) if isinstance(payload, dict) else None)
                    for key, col in _PROMOTE.items()}
        blob_ref = None
        if len(payload_json) > self._blob_threshold:
            cur = self._conn.execute("SELECT COALESCE(MAX(seq),0)+1 AS n FROM messages")
            next_seq = cur.fetchone()["n"]
            blobs = self._dir / "blobs"
            blobs.mkdir(exist_ok=True, mode=0o700)
            blob_path = blobs / f"{next_seq}.bin"
            blob_path.write_bytes(payload_json.encode("utf-8"))
            blob_path.chmod(0o600)
            blob_ref = str(blob_path)
        cur = self._conn.execute(
            "INSERT INTO messages (ts, type, source, hook, url, method, cls, ret, summary, payload, blob_ref)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (time.time(), message.get("type", "send"), message.get("source"),
             promoted["hook"], promoted["url"], promoted["method"], promoted["cls"],
             _short(promoted["ret"]), message.get("summary"), payload_json, blob_ref),
        )
        seq = cur.lastrowid
        self._conn.execute(
            "INSERT INTO messages_fts (rowid, summary, payload) VALUES (?,?,?)",
            (seq, message.get("summary") or "", payload_json),
        )
        self._conn.commit()
        return seq

    def get(self, seq: int) -> dict[str, Any] | None:
        row = self._conn.execute("SELECT * FROM messages WHERE seq=?", (seq,)).fetchone()
        return dict(row) if row else None

    def close(self) -> None:
        self._conn.close()


def _short(value: Any, limit: int = 200) -> str | None:
    if value is None:
        return None
    s = str(value)
    return s if len(s) <= limit else s[:limit]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/unit/test_capture_store.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/pare_frida_mcp/capture/ tests/unit/test_capture_store.py
git commit -m "feat: SQLite capture store with hot-field promotion and blob spill"
```

---

## Task 6: Capture search (promoted columns + FTS5)

**Files:**
- Create: `src/pare_frida_mcp/capture/search.py`
- Test: `tests/unit/test_capture_search.py`

- [ ] **Step 1: Write the failing test**

```python
from pare_frida_mcp.capture.store import CaptureStore
from pare_frida_mcp.capture.search import search_capture

def _seed(tmp_path):
    store = CaptureStore.open(tmp_path, "s", blob_threshold=65536)
    store.write({"type": "send", "source": "h", "summary": "login",
                 "payload": {"url": "https://x/login", "method": "POST"}})
    store.write({"type": "send", "source": "h", "summary": "fetch",
                 "payload": {"url": "https://x/data", "method": "GET"}})
    return store

def test_field_predicate_uses_column(tmp_path):
    store = _seed(tmp_path)
    res = search_capture(store, field="url", contains="login", byte_budget=4096)
    assert res["total"] == 1
    assert res["matches"][0]["method"] == "POST"
    store.close()

def test_fts_text_search(tmp_path):
    store = _seed(tmp_path)
    res = search_capture(store, text="fetch", byte_budget=4096)
    assert res["total"] == 1
    store.close()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_capture_search.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write minimal implementation**

```python
from __future__ import annotations

import json
from typing import Any

from pare_frida_mcp.bounding import bound_text
from pare_frida_mcp.capture.store import CaptureStore

_ALLOWED_FIELDS = {"hook", "url", "method", "cls", "ret", "source", "type"}


def search_capture(store: CaptureStore, *, field: str | None = None,
                   contains: str | None = None, text: str | None = None,
                   limit: int = 50, byte_budget: int = 4096) -> dict[str, Any]:
    conn = store._conn  # internal access within the package
    if text is not None:
        rows = conn.execute(
            "SELECT m.* FROM messages m JOIN messages_fts f ON m.seq=f.rowid "
            "WHERE messages_fts MATCH ? ORDER BY m.seq LIMIT ?",
            (text, limit),
        ).fetchall()
        total = conn.execute(
            "SELECT count(*) AS c FROM messages_fts WHERE messages_fts MATCH ?", (text,)
        ).fetchone()["c"]
    elif field is not None and contains is not None:
        if field not in _ALLOWED_FIELDS:
            raise ValueError(f"field not searchable: {field!r}")
        like = f"%{contains}%"
        rows = conn.execute(
            f"SELECT * FROM messages WHERE {field} LIKE ? ORDER BY seq LIMIT ?", (like, limit)
        ).fetchall()
        total = conn.execute(
            f"SELECT count(*) AS c FROM messages WHERE {field} LIKE ?", (like,)
        ).fetchone()["c"]
    else:
        raise ValueError("provide either text=, or field= + contains=")

    matches = [dict(r) for r in rows]
    blob, truncated = bound_text(json.dumps(matches), byte_budget)
    return {"total": total, "returned": len(matches), "truncated": truncated,
            "matches": json.loads(blob) if not truncated else matches[: max(1, len(matches) // 2)]}
```

Note: `field` is validated against an allowlist before string-interpolation into SQL, so this is not an injection vector. `contains`/`text` are always bound parameters.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/unit/test_capture_search.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/pare_frida_mcp/capture/search.py tests/unit/test_capture_search.py
git commit -m "feat: indexed-column + FTS5 capture search"
```

---

## Task 7: Capture read (bounded slice)

**Files:**
- Create: `src/pare_frida_mcp/capture/read.py`
- Test: `tests/unit/test_capture_read.py`

- [ ] **Step 1: Write the failing test**

```python
from pare_frida_mcp.capture.store import CaptureStore
from pare_frida_mcp.capture.read import read_capture

def test_read_by_seq_bounded(tmp_path):
    store = CaptureStore.open(tmp_path, "s", blob_threshold=65536)
    seq = store.write({"type": "send", "source": "h", "summary": "x",
                       "payload": {"big": "Q" * 10000}})
    res = read_capture(store, seq=seq, byte_budget=256)
    assert res["truncated"] is True
    assert len(res["text"].encode("utf-8")) <= 256
    store.close()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_capture_read.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write minimal implementation**

```python
from __future__ import annotations

import json
from typing import Any

from pare_frida_mcp.bounding import bound_text
from pare_frida_mcp.capture.store import CaptureStore


def read_capture(store: CaptureStore, *, seq: int, offset: int = 0,
                 byte_budget: int = 4096) -> dict[str, Any]:
    row = store.get(seq)
    if row is None:
        raise ValueError(f"no capture record seq={seq}")
    full = json.dumps({k: row[k] for k in row})
    window = full[offset:]
    text, truncated = bound_text(window, byte_budget)
    return {"seq": seq, "offset": offset, "truncated": truncated,
            "next_offset": offset + len(text.encode("utf-8")) if truncated else None,
            "text": text}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/unit/test_capture_read.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/pare_frida_mcp/capture/read.py tests/unit/test_capture_read.py
git commit -m "feat: bounded capture read with continuation offset"
```

---

## Task 8: Tool contract registry + conformance shape

**Files:**
- Create: `src/pare_frida_mcp/contract.py`
- Test: `tests/unit/test_contract.py`

- [ ] **Step 1: Write the failing test**

```python
from pare_frida_mcp.contract import (
    CONTRACT_VERSION, TOOL_SPECS, WorkerContractAdapter,
)

def test_every_tool_has_required_metadata():
    for spec in TOOL_SPECS:
        assert spec.name
        assert spec.risk_tier in {"low", "medium", "high", "critical"}
        assert spec.input_schema.get("type") == "object"
        assert spec.output_schema.get("type") == "object"

def test_execute_script_is_critical_and_write_memory_high():
    by_name = {s.name: s for s in TOOL_SPECS}
    assert by_name["execute_script"].risk_tier == "critical"
    assert by_name["write_memory"].risk_tier == "high"

def test_adapter_matches_agent_core_shape():
    adapter = WorkerContractAdapter()
    assert isinstance(adapter.contract_version(), int)
    tools = adapter.list_tools()
    for t in tools:
        assert {"name", "risk_tier", "input_schema", "output_schema"} <= set(t)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_contract.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write minimal implementation**

```python
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

CONTRACT_VERSION = 1

_OBJ = {"type": "object", "properties": {}}
_BOUNDED_OUT = {"type": "object", "properties": {
    "summary": {"type": "string"},
    "capture": {"type": "object"},
}}


@dataclass(frozen=True)
class ToolSpec:
    name: str
    risk_tier: str
    description: str
    input_schema: dict[str, Any]
    output_schema: dict[str, Any] = field(default_factory=lambda: dict(_BOUNDED_OUT))
    handler: Callable[..., Any] | None = None


def _in(**props) -> dict[str, Any]:
    return {"type": "object", "properties": props}


TOOL_SPECS: list[ToolSpec] = [
    ToolSpec("list_devices", "low", "List Frida devices.", dict(_OBJ)),
    ToolSpec("select_device", "low", "Select a device by id.",
             _in(device_id={"type": "string"})),
    ToolSpec("attach", "medium", "Attach to a process by pid or name.",
             _in(device_id={"type": "string"}, target={"type": "string"})),
    ToolSpec("enumerate_modules", "low", "List loaded modules.",
             _in(session_id={"type": "string"}, filter={"type": "string"})),
    ToolSpec("enumerate_exports", "low", "List exports of a module.",
             _in(session_id={"type": "string"}, module={"type": "string"})),
    ToolSpec("load_script", "medium", "Load a bundled script export set.",
             _in(session_id={"type": "string"}, name={"type": "string"})),
    ToolSpec("execute_script", "critical", "Evaluate arbitrary JS in a session.",
             _in(session_id={"type": "string"}, source={"type": "string"})),
    ToolSpec("java_hook", "medium", "Install an observing Java method hook.",
             _in(session_id={"type": "string"}, cls={"type": "string"},
                 method={"type": "string"}, overload={"type": "string"})),
    ToolSpec("read_memory", "medium", "Read target memory (hex preview).",
             _in(session_id={"type": "string"}, address={"type": "string"},
                 size={"type": "integer"})),
    ToolSpec("scan_memory", "medium", "Scan memory for a byte pattern.",
             _in(session_id={"type": "string"}, pattern={"type": "string"})),
    ToolSpec("write_memory", "high", "Write bytes to target memory.",
             _in(session_id={"type": "string"}, address={"type": "string"},
                 bytes={"type": "string"})),
    ToolSpec("search_capture", "low", "Search captured events.",
             _in(session_id={"type": "string"}, field={"type": "string"},
                 contains={"type": "string"}, text={"type": "string"},
                 byte_budget={"type": "integer"})),
    ToolSpec("read_capture", "low", "Read a captured record slice.",
             _in(session_id={"type": "string"}, seq={"type": "integer"},
                 offset={"type": "integer"}, byte_budget={"type": "integer"})),
]


class WorkerContractAdapter:
    """Exposes the agent_core WorkerContract shape for assert_conformance."""

    def contract_version(self) -> int:
        return CONTRACT_VERSION

    def list_tools(self) -> list[dict[str, Any]]:
        return [
            {"name": s.name, "risk_tier": s.risk_tier,
             "input_schema": s.input_schema, "output_schema": s.output_schema}
            for s in TOOL_SPECS
        ]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/unit/test_contract.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/pare_frida_mcp/contract.py tests/unit/test_contract.py
git commit -m "feat: tool contract registry + WorkerContract adapter"
```

---

## Task 9: SessionManager + batched message pump

**Files:**
- Create: `src/pare_frida_mcp/core/__init__.py` (empty)
- Create: `src/pare_frida_mcp/core/sessions.py`
- Test: `tests/unit/test_sessions_pump.py`

The pump must be testable without a device, so `Session` accepts an injected script object exposing `.on("message", cb)`. The test uses a fake.

- [ ] **Step 1: Write the failing test**

```python
from pare_frida_mcp.config import Config
from pare_frida_mcp.core.sessions import SessionManager

class FakeScript:
    def __init__(self):
        self._cb = None
    def on(self, event, cb):
        self._cb = cb
    def emit(self, message):           # test helper to simulate Frida send()
        self._cb(message, None)

def test_pump_persists_messages(tmp_path):
    cfg = Config(capture_dir=tmp_path, max_tool_bytes=4096,
                 blob_threshold=65536, max_disk_per_session=10**9)
    mgr = SessionManager(cfg)
    script = FakeScript()
    sid = mgr.register_session(script=script, pid=123, name="com.x")
    script.emit({"type": "send", "payload": {"method": "doLogin"}})
    mgr.flush(sid)
    store = mgr.store_for(sid)
    assert store.get(1)["method"] == "doLogin"
    mgr.close_all()

def test_drops_past_queue_bound_with_counter(tmp_path):
    cfg = Config(capture_dir=tmp_path, max_tool_bytes=4096,
                 blob_threshold=65536, max_disk_per_session=10**9)
    mgr = SessionManager(cfg, queue_bound=2)
    script = FakeScript()
    sid = mgr.register_session(script=script, pid=1, name="x")
    for _ in range(5):
        script.emit({"type": "send", "payload": {}})
    assert mgr.dropped_count(sid) == 3
    mgr.close_all()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/unit/test_sessions_pump.py -v`
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write minimal implementation**

```python
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/unit/test_sessions_pump.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/pare_frida_mcp/core/ tests/unit/test_sessions_pump.py
git commit -m "feat: SessionManager + bounded message pump"
```

---

## Task 10: FastMCP server wiring + tool registration

**Files:**
- Create: `src/pare_frida_mcp/server.py`
- Create: `src/pare_frida_mcp/tools.py` (thin handlers; device-coupled ones raise a clear "no device" until Task 12 wires Frida)
- Test: `tests/integration/test_server_list_tools.py`

- [ ] **Step 1: Write the failing test**

```python
import pytest
from pare_frida_mcp.server import build_server

@pytest.mark.asyncio
async def test_list_tools_exposes_all_contract_tools():
    server = build_server()
    tools = await server.list_tools()
    names = {t.name for t in tools}
    assert {"list_devices", "attach", "execute_script", "write_memory",
            "search_capture", "read_capture"} <= names
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/integration/test_server_list_tools.py -v`
Expected: FAIL with `ModuleNotFoundError: pare_frida_mcp.server`

- [ ] **Step 3: Write minimal implementation**

`src/pare_frida_mcp/tools.py`:

```python
from __future__ import annotations

import json

from pare_frida_mcp.config import load_config
from pare_frida_mcp.core.sessions import SessionManager

# Single process-wide manager; populated by attach (Task 12 wires real Frida).
MANAGER = SessionManager(load_config())


async def list_devices() -> str:
    # Real frida enumeration lands in Task 12; placeholder returns empty set
    # so the MCP surface is exercisable without a device.
    return json.dumps({"summary": "no device backend wired yet", "devices": []})
```

`src/pare_frida_mcp/server.py`:

```python
from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from pare_frida_mcp.contract import TOOL_SPECS
from pare_frida_mcp import tools as tools_mod


def build_server() -> FastMCP:
    server = FastMCP("pare-frida-mcp")
    for spec in TOOL_SPECS:
        handler = getattr(tools_mod, spec.name, None)
        if handler is None:
            handler = _stub_for(spec.name)
        server.add_tool(handler, name=spec.name, description=spec.description)
    return server


def _stub_for(name: str):
    async def _stub(**kwargs) -> str:
        import json
        return json.dumps({"summary": f"{name} not implemented in this build"})
    _stub.__name__ = name
    return _stub


def main() -> None:
    build_server().run(transport="stdio")
```

Note: `FastMCP.add_tool(fn, name=, description=)` registers a callable as a tool; inputSchema is derived from the handler signature/contract. Confirm the exact `add_tool` signature against the installed `mcp` version during implementation; if it differs, register via the `@server.tool()` decorator inside a loop-built closure instead.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/integration/test_server_list_tools.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add src/pare_frida_mcp/server.py src/pare_frida_mcp/tools.py tests/integration/test_server_list_tools.py
git commit -m "feat: FastMCP stdio server with contract-driven tool registration"
```

---

## Task 11: agent_core conformance integration test

**Files:**
- Create: `tests/integration/test_conformance.py`

- [ ] **Step 1: Write the test (skips cleanly if agent_core absent)**

```python
import pytest

from pare_frida_mcp.contract import WorkerContractAdapter

def test_assert_conformance_passes():
    conformance = pytest.importorskip("agent_core.workers.conformance")
    conformance.assert_conformance(WorkerContractAdapter())
```

- [ ] **Step 2: Run it**

Run: `pytest tests/integration/test_conformance.py -v`
Expected: PASS if `agent_core` is importable; SKIP otherwise. If it FAILS with an AssertionError, the contract metadata is wrong — fix `contract.py` until `assert_conformance` passes.

- [ ] **Step 3: Commit**

```bash
git add tests/integration/test_conformance.py
git commit -m "test: agent_core contract conformance"
```

---

## Task 12: Bundled Frida agent (frida-compile) + Frida-backed handlers

**Files:**
- Create: `src/pare_frida_mcp/agent/package.json`, `tsconfig.json`, `src/index.ts`
- Create: `Makefile`
- Modify: `src/pare_frida_mcp/tools.py` (wire real frida via `core/devices.py`, `core/scripts.py`, `core/memory.py`, `android/java.py`)
- Test: `tests/device/conftest.py`, `tests/device/test_android_flows.py`

This task is device-coupled. The JS bundle's pure helpers get mocked-global unit tests; the end-to-end flows run only on a real USB device and auto-skip otherwise.

- [ ] **Step 1: Write the agent RPC source** (`src/pare_frida_mcp/agent/src/index.ts`)

```typescript
rpc.exports = {
  modules(filter?: string) {
    return Process.enumerateModules()
      .filter(m => !filter || m.name.includes(filter))
      .map(m => ({ name: m.name, base: m.base.toString(), size: m.size }));
  },
  exports(moduleName: string) {
    return Module.enumerateExports(moduleName)
      .map(e => ({ name: e.name, address: e.address.toString() }));
  },
  javaEnumerate(filter: string) {
    const out: string[] = [];
    Java.perform(() => {
      Java.enumerateLoadedClassesSync()
        .filter(c => c.includes(filter))
        .slice(0, 500)
        .forEach(c => out.push(c));
    });
    return out;
  },
  javaHookInstall(cls: string, method: string, overload?: string) {
    Java.perform(() => {
      const klass = Java.use(cls);
      const target = overload ? klass[method].overload(overload) : klass[method];
      target.implementation = function (...args: any[]) {
        send({ type: "send", source: `${cls}.${method}`,
               payload: { class: cls, method, args: args.map(String) } });
        return target.apply(this, args);
      };
    });
    return { hook: `${cls}.${method}` };
  },
  memRead(address: string, size: number) {
    return ptr(address).readByteArray(size);
  },
  memWrite(address: string, hexBytes: string) {
    const bytes = hexBytes.match(/.{1,2}/g)!.map(b => parseInt(b, 16));
    ptr(address).writeByteArray(bytes);
    return { written: bytes.length };
  },
};
```

- [ ] **Step 2: Write `package.json` + build wiring**

`src/pare_frida_mcp/agent/package.json`:

```json
{
  "name": "pare-frida-mcp-agent",
  "private": true,
  "devDependencies": { "frida-compile": "^16", "@types/frida-gum": "^18" },
  "scripts": { "build": "frida-compile src/index.ts -o dist/agent.js -c" }
}
```

`Makefile`:

```makefile
agent:
	cd src/pare_frida_mcp/agent && npm install && npm run build

test:
	pytest

.PHONY: agent test
```

- [ ] **Step 3: Build the bundle and verify it compiles**

Run: `make agent`
Expected: `src/pare_frida_mcp/agent/dist/agent.js` is produced; non-zero exit fails the task.

- [ ] **Step 4: Write the device test (auto-skips without a device)**

`tests/device/conftest.py`:

```python
import pytest

def pytest_collection_modifyitems(config, items):
    try:
        import frida
        has_device = any(d.type == "usb" for d in frida.enumerate_devices())
    except Exception:
        has_device = False
    if not has_device:
        skip = pytest.mark.skip(reason="no USB device / frida-server")
        for item in items:
            if "device" in str(item.fspath):
                item.add_marker(skip)
```

`tests/device/test_android_flows.py`:

```python
import json
import pytest
from pare_frida_mcp.server import build_server

@pytest.mark.asyncio
async def test_attach_and_enumerate(android_package):
    server = build_server()
    result = await server.call_tool("list_devices", {})
    payload = json.loads(result[0].text if isinstance(result, list) else result)
    assert "devices" in payload
```

(`android_package` is a fixture you define for your test app; keep flows minimal — attach, enumerate_modules, one java_hook, read_memory, search_capture.)

- [ ] **Step 5: Wire real Frida into handlers**

Implement `core/devices.py`, `core/scripts.py`, `core/memory.py`, `android/java.py` and update `tools.py` so each handler: calls Frida / the bundle RPC, shapes a bounded summary via `bounding.bound_text`, and persists detail through `MANAGER`'s store. Run `make agent && pytest -m "not device"` plus device tests on hardware.

Run: `pytest tests/device/test_android_flows.py -v` (on a connected device)
Expected: PASS on device; SKIP otherwise.

- [ ] **Step 6: Commit**

```bash
git add src/pare_frida_mcp/agent/ Makefile src/pare_frida_mcp/core/ src/pare_frida_mcp/android/ src/pare_frida_mcp/tools.py tests/device/
git commit -m "feat: bundled frida agent + frida-backed android tools"
```

---

## Task 13: stdio handshake test + workers.yaml registration docs

**Files:**
- Create: `tests/integration/test_stdio_handshake.py`
- Create: `README.md`

- [ ] **Step 1: Write the stdio handshake test (skips if agent_core absent)**

```python
import pytest

@pytest.mark.asyncio
async def test_stdio_handshake_lists_tools():
    pool_mod = pytest.importorskip("agent_core.workers.client")
    client = pool_mod.MCPClient(transport="stdio", command="pare-frida-mcp")
    await client.connect()
    try:
        await client.initialize()
        result = await client.list_tools()
        names = {t.name for t in result.tools}
        assert "execute_script" in names
    finally:
        await client.close()
```

Confirm `MCPClient`'s stdio constructor kwargs against `agent_core/workers/client.py` during implementation; adjust the constructor call to match.

- [ ] **Step 2: Run it**

Run: `pytest tests/integration/test_stdio_handshake.py -v`
Expected: PASS if agent_core importable and the console script is installed; SKIP otherwise.

- [ ] **Step 3: Write README registration section**

Document the `workers.yaml` entry (from spec §8) and the `risk_overrides:` follow-up:

````markdown
## Registering with PARE

Add to `~/Projects/PARE/workers.yaml`:

```yaml
workers:
  frida:
    command: "pare-frida-mcp"
    transport: stdio
    risk_default: low
    capability_tags: [mobile, dynamic, android, frida]
```

Per-tool HITL gating (PARE-side follow-up): once PARE parses a `risk_overrides:`
section, add patterns escalating `frida_write_memory` → high and
`frida_execute_script` → critical. Until then the worker is gated only at the
`risk_default` floor.
````

- [ ] **Step 4: Commit**

```bash
git add tests/integration/test_stdio_handshake.py README.md
git commit -m "test: stdio handshake; docs: PARE registration"
```

---

## Self-Review

**Spec coverage (§ → task):** §2 contract shape → T8/T11; §3.1 SessionManager+pump → T9; §3.3 execute_script eval (bounded) → T8/T10/T12; §4 capture store + promoted columns + blob spill → T5; §4 search + FTS5 → T6; §4 read → T7; §4.1 output bounding → T4 (applied in T6/T7/T12); §5 config → T2; §5.1 session_id UUID+validation + 0700/0600 perms → T3/T5; §6 error handling (bounded) → T12 handler wiring; §7 unit/integration/device tiers + conformance + pump criterion → T5-T9/T11/T12; §8 tool surface + tiers → T8; §8 workers.yaml + stdio divergence → T10/T13; §8.2 RPC exports → T12. Covered.

**Known follow-ups (not v1 tasks, per spec §9):** iOS pack, bypass tools, vault, search_blob, and PARE-side `risk_overrides` parsing.

**Placeholder note:** Two steps flag SDK-version checks (FastMCP `add_tool` signature in T10; `MCPClient` stdio kwargs in T13) — these are genuine "verify against installed version" actions with a stated fallback, not unfilled placeholders.
```
