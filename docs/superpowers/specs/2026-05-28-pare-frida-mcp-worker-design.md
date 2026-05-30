# pare-frida-mcp — Design Spec

**Date:** 2026-05-28
**Status:** Draft — revised after review panel (2026-05-28); pending user sign-off
**Author:** Shane (with Claude)

## 1. Purpose

`pare-frida-mcp` is a Python MCP server that gives the PARE reverse-engineering agent dynamic-instrumentation capability over Frida 17. It is a stdio worker registered in PARE's `workers.yaml`, exposing tools for device/process discovery, attach/spawn, script execution, native + Java + ObjC hooking, memory inspection, SSL-pinning / jailbreak-and-root bypasses, and on-device data extraction — for both **Android** and **iOS** targets.

> **v1 scope note (post-review):** the *first* shippable increment is **Android-only** and covers the core vertical — device/process discovery, attach, script load + ad-hoc eval, the message pump → capture store, Java hooking, and the full memory-inspection surface (enumerate / read / scan / write). iOS, the SSL/root/jailbreak bypasses, the script vault + maturity ladder, and binary blob search are explicit **fast-follows** (§3, §9). The architecture below is described whole, with each component tagged `[v1]` or `[fast-follow]`.

It is a **clean-room** implementation. The TypeScript project `frida-mcp` (cloned at `~/Projects/frida-mcp`) is used only as conceptual reference; no code is ported verbatim. This avoids the derivative-work question (frida-mcp ships with no license) and lets the worker match PARE's conventions exactly.

### 1.1 Why a new server instead of forking frida-mcp

- **Stack uniformity.** PARE, `agent_core`, and the `apk_re_agents` workers are all Python. A TypeScript worker would be a permanent polyglot maintenance tax (npm/tsc/CI alongside hatch/pytest).
- **PARE already solves persistence.** `agent_core` owns findings storage and `<untrusted-content>` boundary wrapping, so frida-mcp's heaviest subsystem (general-purpose disk-first capture) does not need to be reproduced wholesale.
- **License.** frida-mcp has no LICENSE; clean-room Python sidesteps distribution ambiguity permanently.

### 1.2 Non-goals (v1)

- No GUI / web transport. stdio only.
- No MCP `resources` (see §2/§4 — `agent_core` cannot consume them today).
- No remote/cloud device orchestration beyond what Frida's device manager already exposes (USB + local + remote frida-server).
- **No iOS** in the first slice (ObjC introspection/hooking + jailbreak bypass + keychain/class-dump/crypto extraction are fast-follow).
- **No script vault / maturity ladder** in the first slice — and even when it lands, no automatic "this script worked" detection (vault promotion is always an explicit action).
- **No SSL-pinning / root / jailbreak bypass tools** in the first slice.
- **No binary blob search** (`search_blob`) in the first slice; blob *spill* still exists (memory dumps must land somewhere), but searching spilled blobs is fast-follow.

## 2. Key Constraints (verified against the codebase)

These shaped the design and were confirmed by reading `agent_core` directly:

1. **`agent_core` speaks only `list_tools` / `call_tool`.** It does **not** consume MCP `resources` (`agent_core/workers/client.py:118-135`, `agent_core/workers/discovery.py:25-62`). Resource content blocks would be rendered as useless `repr()` strings.
2. **`agent_core` does zero output truncation.** `agent_core/workers/tool_factory.py:17-25` (`_stringify_result`) concatenates text blocks verbatim into the model context — on both the success and error paths. **The worker is the only line of defense for context size.**
3. **The contract has two layers — a per-tool metadata *shape* (conformance) and the *runtime gating* (which today is workers.yaml-driven). Don't conflate them.**
   - *Shape (we must satisfy):* `agent_core/workers/conformance.py` (`assert_conformance`) requires the worker to expose `contract_version()` (int) and, for every tool from `list_tools`, the fields `name`, `risk_tier` (`low`|`medium`|`high`|`critical`), `input_schema`, `output_schema` (JSON-Schema dicts). Its own docstring calls this "the shape, not the wire." We emit all of it (§8.1).
   - *Runtime gating (how a call is actually gated today):* `agent_core/workers/risk_pool.py` (`RiskAwareToolPool`, v1.5) is the chokepoint. It sets `declared = spec.risk_default` — the **worker-wide** value from `workers.yaml` — then `RiskGate` (`workers/risk.py`) **raises** it via fnmatch override patterns matched against `f"{worker}_{tool}"`, **override-up only** (never lowers). `list_tools` is explicitly *ungated*, so the per-tool `risk_tier` we emit is **not consumed at runtime yet** — it's conformance + forward-compat + the natural "declared floor" if PARE later threads worker-declared tiers through discovery. `types.py:25-32`: `high` → HITL approval, `critical` → HITL + non-empty justification.
   - *Consequence for us:* genuine per-tool HITL on this worker requires PARE to feed `RiskGate` override patterns. PARE's `setup()` currently constructs `RiskGate(overrides=[])` and `registry.py` doesn't parse an overrides key — so this is a **PARE-side follow-up** (`risk_overrides:` in workers.yaml), deliberately deferred until this worker's tool surface exists. See §8 + §9.
4. **The injected Frida agent is always JavaScript**, regardless of host language. "Python server" governs the orchestration layer only; hooks still run as JS inside the target.

**Implications:**
- Every tool MUST self-bound its output — return a compact summary plus a capture ID, never a firehose. Large data is fetched on demand through *tools* (`read_capture`, `search_capture`), not resources. This bound applies to **every** return path including ad-hoc `execute_script` eval results and structured error payloads (§4.1, §6).
- Every tool MUST declare `risk_tier` + `input_schema` + `output_schema` in its `list_tools` entry; the worker runs `assert_conformance` against itself as a test (§7). The per-tool tier table is §8.1.

## 3. Architecture

Layered: a platform-agnostic core, with Android (Java) and iOS (ObjC) packs adding language-specific tools on top, a capture subsystem, and a script vault. Components are tagged `[v1]` (first Android slice) or `[ff]` (fast-follow).

```
pare-frida-mcp/  (Python · FastMCP · stdio)
  pyproject.toml            hatchling build; entry point pare-frida-mcp = "pare_frida_mcp.server:main"
  src/pare_frida_mcp/
    server.py               [v1] FastMCP app; registers tools w/ contract metadata; stdio lifecycle
    contract.py             [v1] contract_version() + per-tool risk_tier/input_schema/output_schema
    config.py               [v1] env-driven config (capture dir, size caps, db path)
    core/
      devices.py            [v1] enumerate / select device (usb · local · remote)
      sessions.py           [v1] SessionManager: attach/spawn, registry, message pump
      scripts.py            [v1] load/unload JS, call RPC exports, execute ad-hoc (eval)
      memory.py             [v1] modules/exports, read/scan/write
      native.py             [ff] native function hooks, backtraces
    android/
      java.py               [v1] class/method enum, live instances, heap, Java hooks
      bypass.py             [ff] SSL pinning + root detection (stock attempts, diagnostic)
    ios/                    [ff] entire iOS pack is fast-follow
      objc.py               [ff] class/method/ivar introspection, live instances
      hooks.py              [ff] ObjC method hooks
      bypass.py             [ff] SSL pinning + jailbreak detection
      extract.py            [ff] keychain, class-dump, crypto monitor
    capture/
      store.py              [v1] SQLite per-session store; structured records; blob spill
      search.py             [v1] field-aware (promoted columns) + regex over messages; [ff] search_blob
      read.py               [v1] read_capture(id, offset, limit) — bounded
    vault/                  [ff] entire vault is fast-follow
      store.py              [ff] .js files on disk + SQLite metadata index
      tools.py              [ff] save_to_vault, search_vault, get_vault_script, run_vault_script
    agent/                  [v1] the injected Frida agent (JS — built with frida-compile)
      src/                  [v1] Java helpers + hook installers; [ff] objc helpers, stock bypasses
      dist/agent.js         [v1] compiled bundle, checked in (or built in CI)
  tests/
    unit/                   pure-Python logic (capture, search, record shaping, bounding)
    integration/            MCP handshake, assert_conformance, tool listing, error paths (no device)
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

1. Agent calls `java_hook` (v1; `objc_hook` / `native_hook` are fast-follow) with a target spec.
2. Python tool calls the bundled agent's RPC export to install the hook; returns immediately with a hook id + compact confirmation.
3. As the hook fires, the in-target agent `send()`s structured payloads. The message pump persists each as a record in the session's SQLite store.
4. The agent later calls `search_capture` / `read_capture` to pull only the records it needs — bounded, never the whole stream.

### 3.3 Injected-agent strategy (hybrid)

The in-target code is JavaScript either way. We split it:

- **Bundled agent** (`agent/`, compiled via `frida-compile`): the heavy, reusable, *tested* helpers — Java introspection and hook installers in v1 (ObjC helpers + stock bypasses fast-follow). Exposed as RPC exports the Python side calls (`script.exports.java_enumerate(...)`). Real JS tooling, no string-escaping hazards, unit-testable. The v1 RPC export surface is enumerated in §8.2.
- **Ad-hoc eval** (`execute_script` tool): a thin escape hatch that evaluates arbitrary JS in a session for the open-ended RE workflow — improvising during an engagement. **Eval runs within the bundled agent's loaded script context**, so improvised code can call the bundle's RPC helpers and share its state — this is what makes the (fast-follow) improvise → vault → promote ladder coherent: every rung runs in one runtime. Its return value is **not** exempt from the output bound: eval results route through the same summary + capture-handle path as every other tool (§4.1), spilling to a blob when large. `execute_script` is the single most powerful tool in the surface and is tiered **`critical`** (§8.1).

Trade-off accepted: this reintroduces a small `frida-compile` build step. It is a build artifact (checked-in `dist/agent.js`), not an ongoing polyglot surface. CI builds and verifies it.

### 3.4 Script vault & the maturity ladder  `[fast-follow]`

> Deferred past v1. Captured here so the v1 `execute_script` design (shared script context, §3.3) stays forward-compatible. When it lands, `run_vault_script` is tiered **`high`** and MUST enforce provenance: refuse to run when the live target's package/bundle-id doesn't match the stored `target_hint` unless explicitly overridden, and surface the script body for HITL approval. `save_to_vault` is also **`high`** (it persists injectable code).

Three rungs, increasing ceremony:

1. **Improvise** — `execute_script` evals ad-hoc JS.
2. **Vault** — `save_to_vault(name, script, tags, notes, platform, target_hint)` persists a working snippet as a `.js` file plus a SQLite metadata row. `search_vault` / `get_vault_script` / `run_vault_script(name, args)` make it reusable at runtime. Search returns **compact metadata only**; the body is fetched on demand.
3. **Promote** — a proven vault script is folded into the bundled agent as an RPC export. Deliberately a code change + `frida-compile` rebuild + a test, documented as a procedure (not a tool), so the agent bundle stays curated and trustworthy.

Provenance (origin session, platform, target hint, args schema, "why it worked" note) is stored so a stored script is safe to re-run later — it is executable code injected into a target.

### 3.5 Bypass tools are diagnostic  `[fast-follow]`

> Deferred past v1. SSL-pinning, root-detection, and jailbreak-detection bypasses follow "try stock → fall back to RE." Each bypass tool:

- attempts the known stock defeats for the platform,
- returns a **verdict** and, where detectable, **which check tripped**,
- on failure, points the agent toward the manual RE workflow (introspection + hooking).

They owe the caller a result, not just an attempt. Two constraints when this lands: (1) the verdict is **"hook installed"**, not "pinning defeated", unless real traffic confirms it — a hook can install while the app pins at an uncovered layer (Flutter/BoringSSL, native cronet); (2) these tools install behavior-altering `Interceptor.replace` hooks, so "diagnostic" does not mean low blast radius — they are tiered **`high`**.

## 4. Capture store (SQLite)

One SQLite database per session (`<capture_dir>/<session_id>/capture.db`, where `session_id` is a server-generated UUID — see §5). Stdlib `sqlite3`, WAL mode, zero extra deps.

```sql
CREATE TABLE messages (
  seq        INTEGER PRIMARY KEY,      -- monotonic per session
  ts         REAL NOT NULL,            -- epoch seconds
  type       TEXT NOT NULL,            -- 'send' | 'error'
  source     TEXT,                     -- script/hook id that emitted it
  -- promoted hot fields: extracted from the payload at write time so search
  -- is an indexed lookup, NOT a per-row json_extract scan.
  hook       TEXT,                     -- logical hook/event name
  url        TEXT,                     -- network-ish events
  method     TEXT,                     -- java/objc/native method or HTTP verb
  cls        TEXT,                     -- class / module
  ret        TEXT,                     -- short repr of return value
  summary    TEXT,                     -- short, human-readable preview
  payload    TEXT,                     -- JSON (full structured payload)
  blob_ref   TEXT                      -- file path when payload too large to inline
);
CREATE INDEX idx_messages_ts     ON messages(ts);
CREATE INDEX idx_messages_type   ON messages(type);
CREATE INDEX idx_messages_source ON messages(source);
CREATE INDEX idx_messages_hook   ON messages(hook);
CREATE INDEX idx_messages_url    ON messages(url);
CREATE INDEX idx_messages_method ON messages(method);
CREATE INDEX idx_messages_cls    ON messages(cls);
-- substring/regex over text uses FTS5, not LIKE over the whole table:
CREATE VIRTUAL TABLE messages_fts USING fts5(summary, payload, content='messages', content_rowid='seq');
```

- **Field-aware search** runs against the **promoted, indexed columns** (`url`, `method`, `cls`, `hook`, …), populated by the message pump at write time. This is the fix for the review finding that `json_extract(payload, '$.path')` predicates force a full table scan on every search — at hundreds of thousands of events a chatty hook would make search O(n). Free-text substring/regex search goes through the `messages_fts` FTS5 index over `summary`/`payload`. `json_extract` remains available only as a fallback for rare ad-hoc paths not promoted to a column. Pagination via `LIMIT`/`OFFSET`.
- **Blob spill:** payloads above a size threshold are written to `<capture_dir>/<session_id>/blobs/<seq>.bin`; the row keeps a `blob_ref` and a bounded preview. **Previews of binary data are hex-escaped and length-capped** (never raw bytes interpolated into a summary — that would inject control chars / break UTF-8 / expand unpredictably in context). Binary captures (memory dumps from `read_memory`) go here too.
- **`search_blob`** (scan a spilled blob for byte/string patterns) is **`[fast-follow]`**; when it lands it returns bounded, hex-escaped windows with a fixed max match count.

All search/read is worker-side; only matches cross into the model context, and every result obeys the §4.1 bound **after** `LIMIT` is applied (wide rows × LIMIT must still be truncated, reporting the total match count).

### 4.1 Output-bounding contract

Every tool returns at most a configurable cap (`PARE_FRIDA_MAX_TOOL_BYTES`, default ~4 KB of text). The cap defaults can be tuned later (§9); the **behavior** is fixed contract, not a knob:

- When a result fits, it is returned whole.
- When it exceeds the cap, the tool returns a compact summary + counts + a `capture` handle (`{session_id, query}` or `{session_id, seq}`) the agent uses to drill in via `read_capture` / `search_capture`. The truncation happens on a UTF-8 character boundary (never mid-codepoint), and the summary clearly states it was truncated and how to fetch the rest.
- **This applies to EVERY return path** — including `execute_script` ad-hoc eval results (§3.3) and structured error payloads (§6). There is no tool whose output bypasses the cap. Large eval returns spill to a blob just like captured payloads.
- `read_capture` / `search_capture` accept an explicit byte budget so the agent can pull "as much as fits in one turn" rather than blind fixed-size slices — this keeps the summary+handle pattern from degrading into a chatty multi-round-trip on a small-context local model.

## 5. Configuration

Environment variables (with sane defaults), consumed in `config.py`:

- `PARE_FRIDA_CAPTURE_DIR` — base dir for session DBs and blobs.
- `PARE_FRIDA_MAX_TOOL_BYTES` — per-tool output cap (default ~4 KB).
- `PARE_FRIDA_BLOB_THRESHOLD` — payload size above which we spill to a blob file.
- `PARE_FRIDA_MAX_DISK_PER_SESSION` — disk quota per session (eviction/refusal when exceeded).
- `PARE_FRIDA_VAULT_DIR` — vault scripts + index location. `[fast-follow]`

### 5.1 Session identity & on-disk safety

- **`session_id` is a server-generated UUID.** It is never derived from caller arguments, target-supplied names, or model output. Before any path join it is validated against `^[0-9a-f-]{36}$`. This closes the path-traversal vector the review flagged: a `session_id` like `../../vault/x` could otherwise escape `CAPTURE_DIR` and clobber another session's DB or (fast-follow) vault scripts.
- **Capture artifacts hold plaintext secrets.** Session DBs and blobs can contain intercepted credentials, decrypted memory, and (fast-follow) keychain items. The capture dir is created `0700`, files `0600`. The disk quota (`MAX_DISK_PER_SESSION`) is a DoS guard on *volume*, not a confidentiality control.
- **Retention is explicit, not automatic.** v1 does not auto-expire captures; the operator deletes them. This is stated so the agent and operator know nothing is cleaned up behind them.

## 6. Error handling

- Frida errors (process gone, ptrace denied, frida-server missing/version-mismatch) are caught and returned as structured, actionable tool errors — never raw stack traces dumped into context. Errors map to `agent_core` `WorkerError` codes (`types.py:41-49`): e.g. upstream-unreachable `-32001`, session-expired `-32002`, resource-limit `-32004`.
- **Error payloads obey the §4.1 byte cap too.** A Frida exception carrying a JS stack, or a bundled-agent load trace, is summarized and capped — never interpolated verbatim into context (this was a flagged sink-bypass: `agent_core` returns error text to the model untruncated, so the worker must bound it).
- Spawn-with-attach-fallback is **opt-in** per call; auto-resume of a spawned process is also opt-in (avoids accidentally resuming a target). Note the RE-timing reason spawn exists at all: to install hooks **while the process is suspended**, then resume — otherwise early anti-debug / cert-pinning-at-init fires before hooks land. The opt-in resume is therefore also the "hooks are in place, go" signal, not just a safety toggle. Frida-detection / anti-debug on hardened targets is a known limitation, acceptable under PARE's benign-but-untrusted threat model.
- Disk-quota exceeded → tool returns a clear error and stops writing rather than filling the disk.
- Bundled-agent load failure → reported once, with remediation (rebuild bundle), and Java tools degrade to a clear "agent unavailable" error rather than silent failure.

## 7. Testing strategy

Mirrors `apk_re_agents`: pytest + pytest-asyncio, three tiers.

- **unit/** — capture record shaping + hot-field promotion, SQLite search (indexed-column + FTS5), blob spill/threshold, hex-escaped preview bounding, output-bounding (incl. eval + error paths), error→`WorkerError` mapping, `session_id` validation. No device, no Frida.
- **integration/** — start the server, MCP handshake, `list_tools`, and **`assert_conformance(worker)`** from `agent_core.workers.conformance` as a hard gate (every tool must carry `risk_tier` + `input_schema` + `output_schema`; `contract_version()` present). Also: stdio handshake against `MCPClient(command="pare-frida-mcp")` — no existing PARE worker uses stdio yet, so this path is load-bearing-but-unproven and must be covered. Input-schema validation, error paths. No device.
- **device/** — real USB Android flows (attach, load script, `execute_script`, java_hook, memory read/scan/write, capture search/read). Auto-skip when no device/frida-server is present (matches `test:device` convention).
- **agent bundle** — the JS helpers get their own unit checks. Because Frida globals (`Java`, `Interceptor`, `Module`, `Memory`) don't exist outside a target, the bundle's pure logic (payload shaping, arg serialization) is factored to be testable with those globals **mocked/stubbed**; the genuinely device-coupled paths are covered in the `device/` tier. CI runs `frida-compile` and fails the build if the bundle does not compile.
- **message-pump acceptance criterion** — under a synthetic high-frequency `send()` flood, the pump must (a) not block instrumentation on disk I/O (batched WAL writes), and (b) not lose records up to the configured queue bound; on bound-exceed it drops with a counted, surfaced warning rather than unbounded memory growth.

## 8. PARE integration

Registered as a stdio worker in `~/Projects/PARE/workers.yaml`:

```yaml
workers:
  frida:
    command: "pare-frida-mcp"        # console-script entry point
    transport: stdio
    risk_default: low                # worker-wide floor; escalate dangerous tools via risk_overrides (follow-up)
    capability_tags: [mobile, dynamic, android, frida]   # ios added at fast-follow
  # --- PARE-side follow-up, NOT part of this worker (added once the surface is real) ---
  # risk_overrides:
  #   - ["frida_write_memory", "high"]
  #   - ["frida_execute_script", "critical"]
```

How gating actually works (§2 item 3): PARE's `RiskAwareToolPool` takes `declared = risk_default` (worker-wide) and `RiskGate` **raises** specific tools via fnmatch name-pattern overrides (`{worker}_{tool}`), **override-up only**. So the intended shape is **`risk_default: low`, escalate the dangerous few** — you cannot set the worker `high` and carve harmless tools back down. Per-tool escalation is therefore an **operator-side `risk_overrides:` follow-up on PARE** (the override engine already supports patterns; PARE's `setup()` just feeds it `[]` today, and `registry.py` doesn't parse the key yet). The worker still emits per-tool `risk_tier` in `list_tools` (§8.1) for conformance and as the natural floor if PARE later honors worker-declared tiers — but that emission does not by itself gate anything at runtime.

The FastMCP entry point runs `server.run(transport="stdio")` — note this **diverges** from the `apk_re_agents` template, whose servers run `transport="streamable-http"` with host/port. Mirror apk_re_agents for layout, packaging (hatch), and test structure; do **not** mirror its transport.

Findings storage and `<untrusted-content>` wrapping remain `agent_core`'s responsibility; the worker returns raw (but bounded) tool output.

### 8.1 v1 tool surface & risk tiers

Each tool ships `risk_tier` + `input_schema` + `output_schema` in `list_tools` (conformance). These tiers are the worker's own assessment; they also tell PARE exactly which tools the `risk_overrides:` follow-up should escalate. Output schemas all follow the §4.1 bounded shape (summary fields + optional `capture` handle). Tiers:

| Tool | Tier | Input (key args) | Output summary |
|------|------|------------------|----------------|
| `list_devices` | low | — | devices: id/name/type |
| `select_device` | low | `device_id` | selected device |
| `attach` | medium | `device_id?`, `target` (pid or process name) | `session_id`, pid, name |
| `enumerate_modules` | low | `session_id`, `filter?` | module names/base/size (bounded) |
| `enumerate_exports` | low | `session_id`, `module` | export names/addrs (bounded) |
| `load_script` | medium | `session_id`, `name` (bundled export set) | script id, exports loaded |
| `execute_script` | **critical** | `session_id`, `source` (arbitrary JS) | bounded result + `capture` handle |
| `java_hook` | medium | `session_id`, `cls`, `method`, `overload?` | hook id, install confirmation |
| `read_memory` | medium | `session_id`, `address`, `size` | hex-escaped bounded preview + `blob_ref` |
| `scan_memory` | medium | `session_id`, `pattern`, `ranges?` | match addrs (bounded) |
| `write_memory` | **high** | `session_id`, `address`, `bytes` | bytes written, verify readback |
| `search_capture` | low | `session_id`, field/text predicates, `byte_budget?` | matching records (bounded) + total count |
| `read_capture` | low | `session_id`, `seq` or `query`, `offset?`, `byte_budget?` | bounded slice + continuation handle |

Once PARE feeds the matching `risk_overrides:` (follow-up), `critical` (`execute_script`) requires HITL + a non-empty justification and `high` (`write_memory`) requires HITL approval, while everything else auto-executes with an audit entry. **Until that follow-up lands, runtime gating is only the worker-wide `risk_default`** (`low` → all tools auto-execute) — so do not treat this worker as HITL-gated until PARE's `risk_overrides` is wired. Independent of tiers: ambiguous Java overloads MUST error rather than guess; hooks restore on unload so the target isn't left patched after the session.

### 8.2 v1 bundled-agent RPC exports

The compiled `dist/agent.js` exposes exactly these to the Python side in v1 (everything else is improvised via `execute_script` until promoted):

- `java_enumerate(filter)` — classes/methods matching a filter, bounded.
- `java_instances(cls)` — live instances of a class.
- `java_hook_install(cls, method, overload)` — install an observing hook; returns a hook id; emits structured `send()` payloads the pump captures.
- `java_hook_remove(hook_id)` — uninstall + restore.
- `mem_read(address, size)` / `mem_scan(pattern, ranges)` / `mem_write(address, bytes)` — memory primitives backing the `*_memory` tools.
- `modules()` / `exports(module)` — backing the enumerate tools.

ObjC helpers and stock-bypass installers are fast-follow additions to this surface.

## 9. Open questions / deferred

**Tunable (not blocking the plan):**
- Exact per-tool byte cap and blob threshold defaults — tune during implementation against real captures. (The §4.1 *behavior* is fixed; only the numbers are open.)
- Message-pump batch size / flush interval / queue bound — tune against a chatty real hook.

**Fast-follow roadmap (post-v1, in rough order):**
1. iOS pack — ObjC introspection + hooks, then jailbreak/SSL bypass, then `extract.py` (keychain / class-dump / crypto monitor).
2. Android `bypass.py` (SSL pinning + root detection) and `core/native.py` (native hooks + backtraces).
3. Script vault + improvise → vault → promote ladder (§3.4), with provenance enforcement.
4. `search_blob` over spilled binary captures (§4).
5. `scan_memory` — stub removed from v1 contract; reintroduce as a thin `Memory.scanSync` pass-through when needed.

**v1-built but tracked-as-incomplete (correctness / robustness, not feature gaps):**
- **`PARE_FRIDA_MAX_DISK_PER_SESSION` is not yet enforced.** The config knob exists; `CaptureStore.write` does not check it. Add a `du`-style check (db file size + blob dir size) before INSERT and refuse with a structured error when over quota (§5, §6).
- **Pump batched WAL writes & background flush (§7 acceptance criterion).** Current pump commits per row inside `flush()`, and `flush()` only runs on demand from capture-read tools. Real chatty hooks need (a) a periodic flusher thread that drains the queue without a tool call, and (b) batched inserts inside a single transaction.
- **`_on_message` thread safety.** Frida delivers messages on its own thread; concurrent `flush()` from a tool thread races the deque. Add a lock or swap to `queue.SimpleQueue`.
- **`search_capture` truncation fallback.** When results exceed `byte_budget`, it currently returns `matches[:len//2]` without re-bounding; a halving loop or a force-`read_capture` fallback is the correct shape.
- **Spawn semantics.** `attach` covers pid-or-name; the spec §6 spawn-with-suspend + opt-in-resume pattern (needed for early-anti-debug targets) is not implemented in v1.

**External dependency (PARE-side, deferred by design):**
- The enforcement *machinery* shipped (agent_core v1.5 `RiskAwareToolPool` — approval, audit, CLI prompt, fail-closed). What remains is the **`risk_overrides:` follow-up**: parse a patterns section in `workers.yaml` into the `(pattern, tier)` list `RiskGate` already accepts, and add the `frida` worker entry escalating `frida_write_memory` → high and `frida_execute_script` → critical. Deliberately deferred until this worker's tool surface is real (so the dangerous set is known). **Until it lands, treat this worker as ungated** beyond its `risk_default: low` floor.
- Open design choice (defer until tools exist): operator-side `risk_overrides` alone (cheaper) vs. threading worker-declared per-tool tiers through the contract/discovery (better long-term home; they compose — worker floor + operator escalation).
- Whether to add a thin MCP `resources` view later, *if* `agent_core` grows resource consumption (forward-compatible, not built now).
