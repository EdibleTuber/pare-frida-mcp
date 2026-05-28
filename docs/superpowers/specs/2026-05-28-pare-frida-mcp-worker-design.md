# pare-frida-mcp — Design Spec

**Date:** 2026-05-28
**Status:** Draft (pending panel + user review)
**Author:** Shane (with Claude)

## 1. Purpose

`pare-frida-mcp` is a Python MCP server that gives the PARE reverse-engineering agent dynamic-instrumentation capability over Frida 17. It is a stdio worker registered in PARE's `workers.yaml`, exposing tools for device/process discovery, attach/spawn, script execution, native + Java + ObjC hooking, memory inspection, SSL-pinning / jailbreak-and-root bypasses, and on-device data extraction — for both **Android** and **iOS** targets.

It is a **clean-room** implementation. The TypeScript project `frida-mcp` (cloned at `~/Projects/frida-mcp`) is used only as conceptual reference; no code is ported verbatim. This avoids the derivative-work question (frida-mcp ships with no license) and lets the worker match PARE's conventions exactly.

### 1.1 Why a new server instead of forking frida-mcp

- **Stack uniformity.** PARE, `agent_core`, and the `apk_re_agents` workers are all Python. A TypeScript worker would be a permanent polyglot maintenance tax (npm/tsc/CI alongside hatch/pytest).
- **PARE already solves persistence.** `agent_core` owns findings storage and `<untrusted-content>` boundary wrapping, so frida-mcp's heaviest subsystem (general-purpose disk-first capture) does not need to be reproduced wholesale.
- **License.** frida-mcp has no LICENSE; clean-room Python sidesteps distribution ambiguity permanently.

### 1.2 Non-goals (v1)

- No GUI / web transport. stdio only.
- No automatic "this script worked" detection (vault promotion is an explicit action).
- No MCP `resources` (see §4 — `agent_core` cannot consume them today).
- No remote/cloud device orchestration beyond what Frida's device manager already exposes (USB + local + remote frida-server).

## 2. Key Constraints (verified against the codebase)

These shaped the design and were confirmed by reading `agent_core` directly:

1. **`agent_core` speaks only `list_tools` / `call_tool`.** It does **not** consume MCP `resources` (`client.py:118-135`, `discovery.py:25-62`). Resource content blocks would be rendered as useless `repr()` strings.
2. **`agent_core` does zero output truncation.** `tool_factory.py:17-25` (`_stringify_result`) concatenates text blocks verbatim into the model context. **The worker is the only line of defense for context size.**
3. **Risk tiers / capability_tags live in `workers.yaml`**, not over MCP. The MCP surface is just tool name + description + input schema.
4. **The injected Frida agent is always JavaScript**, regardless of host language. "Python server" governs the orchestration layer only; hooks still run as JS inside the target.

**Implication:** every tool MUST self-bound its output — return a compact summary plus a capture ID, never a firehose. Large data is fetched on demand through *tools* (`read_capture`, `search_capture`), not resources.

## 3. Architecture

Layered: a platform-agnostic core, with Android (Java) and iOS (ObjC) packs adding language-specific tools on top, a capture subsystem, and a script vault.

```
pare-frida-mcp/  (Python · FastMCP · stdio)
  pyproject.toml            hatchling build; entry point pare-frida-mcp = "pare_frida_mcp.server:main"
  src/pare_frida_mcp/
    server.py               FastMCP app; registers all tools; lifecycle/shutdown
    config.py               env-driven config (capture dir, size caps, db path)
    core/
      devices.py            enumerate / select device (usb · local · remote)
      sessions.py           SessionManager: attach/spawn, registry, message pump
      scripts.py            load/unload JS, call RPC exports, execute ad-hoc (eval)
      memory.py             modules/exports, read/write/scan
      native.py             native function hooks, backtraces
    android/
      java.py               class/method enum, live instances, heap, Java hooks
      bypass.py             SSL pinning + root detection (stock attempts, diagnostic)
    ios/
      objc.py               class/method/ivar introspection, live instances
      hooks.py              ObjC method hooks
      bypass.py             SSL pinning + jailbreak detection (stock attempts, diagnostic)
      extract.py            keychain, class-dump, crypto monitor      [fast-follow]
    capture/
      store.py              SQLite per-session store; structured records; blob spill
      search.py             field-aware (jq-style) + regex; messages & blobs
      read.py               read_capture(id, offset, limit) — bounded
    vault/
      store.py              .js files on disk + SQLite metadata index
      tools.py              save_to_vault, search_vault, get_vault_script, run_vault_script
    agent/                  the injected Frida agent (JS — built with frida-compile)
      src/                  TS/JS source: objc/java helpers, hooking installers, stock bypasses
      dist/agent.js         compiled bundle, checked in (or built in CI)
  tests/
    unit/                   pure-Python logic (capture, search, vault, record shaping)
    integration/            MCP handshake, tool listing, error paths (no device)
    device/                 real USB device tests (auto-skip when absent)
```

### 3.1 Component responsibilities

- **`server.py`** — constructs the `FastMCP` instance, imports each pack's `register(server, deps)` function, runs over stdio. No business logic.
- **`SessionManager`** — owns Frida `Device`/`Session`/`Script` objects keyed by a session id. Runs the **message pump**: subscribes to each script's `message` signal, converts each message into a structured record, and writes it to the capture store. Under high-frequency hooks the pump batches writes (queue + periodic / N-row flush, WAL mode) so a chatty hook cannot stall instrumentation on synchronous disk I/O. Sessions are in-memory; an MCP restart loses them (documented behavior — the agent re-attaches).
- **Core packs (`memory`, `native`, `scripts`)** — platform-agnostic primitives usable on any target.
- **Android / iOS packs** — language-specific tools. Heavy logic lives in the bundled agent (§3.3); the Python tool is a thin RPC caller that shapes the result into a bounded summary.
- **Capture subsystem** — the single sink for all instrumentation output and the search/read surface over it.
- **Vault** — reusable script library with the improvise → vault → promote ladder (§3.4).

### 3.2 Data flow (representative: hooking a method)

1. Agent calls `java_hook` / `objc_hook` / `native_hook` with a target spec.
2. Python tool calls the bundled agent's RPC export to install the hook; returns immediately with a hook id + compact confirmation.
3. As the hook fires, the in-target agent `send()`s structured payloads. The message pump persists each as a record in the session's SQLite store.
4. The agent later calls `search_capture` / `read_capture` to pull only the records it needs — bounded, never the whole stream.

### 3.3 Injected-agent strategy (hybrid)

The in-target code is JavaScript either way. We split it:

- **Bundled agent** (`agent/`, compiled via `frida-compile`): the heavy, reusable, *tested* helpers — ObjC/Java introspection, hook installers, and the **stock bypasses**. Exposed as RPC exports the Python side calls (`script.exports.objc_enumerate(...)`). Real JS tooling, no string-escaping hazards, unit-testable.
- **Ad-hoc eval** (`execute_script` tool): a thin escape hatch that evaluates arbitrary JS in a session for the open-ended RE workflow — improvising during an engagement.

Trade-off accepted: this reintroduces a small `frida-compile` build step. It is a build artifact (checked-in `dist/agent.js`), not an ongoing polyglot surface. CI builds and verifies it.

### 3.4 Script vault & the maturity ladder

Three rungs, increasing ceremony:

1. **Improvise** — `execute_script` evals ad-hoc JS.
2. **Vault** — `save_to_vault(name, script, tags, notes, platform, target_hint)` persists a working snippet as a `.js` file plus a SQLite metadata row. `search_vault` / `get_vault_script` / `run_vault_script(name, args)` make it reusable at runtime. Search returns **compact metadata only**; the body is fetched on demand.
3. **Promote** — a proven vault script is folded into the bundled agent as an RPC export. Deliberately a code change + `frida-compile` rebuild + a test, documented as a procedure (not a tool), so the agent bundle stays curated and trustworthy.

Provenance (origin session, platform, target hint, args schema, "why it worked" note) is stored so a stored script is safe to re-run later — it is executable code injected into a target.

### 3.5 Bypass tools are diagnostic

SSL-pinning, root-detection, and jailbreak-detection bypasses follow "try stock → fall back to RE." Each bypass tool:

- attempts the known stock defeats for the platform,
- returns a **verdict** (worked / partially / failed) and, where detectable, **which check tripped**,
- on failure, points the agent toward the manual RE workflow (introspection + hooking).

They owe the caller a result, not just an attempt.

## 4. Capture store (SQLite)

One SQLite database per session (`<capture_dir>/<session_id>.db`). Stdlib `sqlite3`, zero extra deps.

```sql
CREATE TABLE messages (
  seq        INTEGER PRIMARY KEY,      -- monotonic per session
  ts         REAL NOT NULL,            -- epoch seconds
  type       TEXT NOT NULL,            -- 'send' | 'error'
  source     TEXT,                     -- script/hook id that emitted it
  summary    TEXT,                     -- short, human-readable preview
  payload    TEXT,                     -- JSON (full structured payload)
  blob_ref   TEXT                      -- file path when payload too large to inline
);
CREATE INDEX idx_messages_ts     ON messages(ts);
CREATE INDEX idx_messages_type   ON messages(type);
CREATE INDEX idx_messages_source ON messages(source);
```

- **Field-aware search** via `json_extract(payload, '$.path')` predicates (e.g., `args.url contains "login"`), plus regex/substring fallback over `summary`/`payload`. Pagination via `LIMIT`/`OFFSET`.
- **Blob spill:** payloads above a size threshold are written to `<capture_dir>/<session_id>/blobs/<seq>.bin`; the row keeps a `blob_ref` and a truncated preview. Binary captures (memory dumps) go here too.
- **`search_blob(ref, pattern, encoding, limit)`** scans a spilled blob for byte/string patterns, returning offsets + surrounding bytes.

All search/read is worker-side; only matches cross into the model context.

### 4.1 Output-bounding contract

Every tool returns at most a configurable cap (default e.g. 4 KB of text). When a result exceeds it, the tool returns a summary + counts + the `capture` handle the agent uses to drill in. No tool ever returns an unbounded stream.

## 5. Configuration

Environment variables (with sane defaults), consumed in `config.py`:

- `PARE_FRIDA_CAPTURE_DIR` — base dir for session DBs and blobs.
- `PARE_FRIDA_MAX_TOOL_BYTES` — per-tool output cap (default ~4 KB).
- `PARE_FRIDA_BLOB_THRESHOLD` — payload size above which we spill to a blob file.
- `PARE_FRIDA_MAX_DISK_PER_SESSION` — disk quota per session (eviction/refusal when exceeded).
- `PARE_FRIDA_VAULT_DIR` — vault scripts + index location.

## 6. Error handling

- Frida errors (process gone, ptrace denied, frida-server missing/version-mismatch) are caught and returned as structured, actionable tool errors — never raw stack traces dumped into context.
- Spawn-with-attach-fallback is **opt-in** per call; auto-resume of a spawned process is also opt-in (avoids accidentally resuming a target).
- Disk-quota exceeded → tool returns a clear error and stops writing rather than filling the disk.
- Bundled-agent load failure → reported once, with remediation (rebuild bundle), and Java/ObjC tools degrade to a clear "agent unavailable" error rather than silent failure.

## 7. Testing strategy

Mirrors `apk_re_agents`: pytest + pytest-asyncio, three tiers.

- **unit/** — capture record shaping, SQLite search (field-aware + regex), blob spill/threshold, vault store, output-bounding, error mapping. No device, no Frida.
- **integration/** — start the server, MCP handshake, `list_tools`, input-schema validation, error paths. No device.
- **device/** — real USB device flows (attach, load script, hook, capture, bypass). Auto-skip when no device/frida-server is present (matches `test:device` convention).
- **agent bundle** — the JS helpers get their own unit checks; CI runs `frida-compile` and fails the build if the bundle does not compile.

## 8. PARE integration

Registered as a stdio worker in `~/Projects/PARE/workers.yaml`:

```yaml
workers:
  frida:
    command: "pare-frida-mcp"        # console-script entry point
    transport: stdio
    risk_default: medium
    capability_tags: [mobile, dynamic, android, ios, frida]
```

Risk-tier guidance for PARE's HITL gates (declared on PARE's side):
- **medium:** enumerate, attach, load/execute script, hooks, search/read capture, vault read/run.
- **high:** memory writes, spawn + auto-resume, keychain/data extraction, full memory dumps.

Findings storage and `<untrusted-content>` wrapping remain `agent_core`'s responsibility; the worker returns raw (but bounded) tool output.

## 9. Open questions / deferred

- Exact per-tool byte cap and blob threshold defaults — tune during implementation against real captures.
- iOS `extract.py` (keychain / class-dump / crypto monitor) is a **fast-follow** after the introspection + hooking + bypass core lands.
- Whether to add a thin MCP `resources` view later, *if* `agent_core` grows resource consumption (forward-compatible, not built now).
