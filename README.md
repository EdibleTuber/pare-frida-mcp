# pare-frida-mcp

A Python FastMCP stdio worker that gives the PARE reverse-engineering agent
Frida 17 dynamic-instrumentation tools for Android (v1).

## Role in the RE loop

These tools serve the **Verify** beat of PARE's reverse-engineering loop ([Orient → Enumerate → Hypothesize → Verify → Re-orient](https://github.com/EdibleTuber/PARE#how-pare-works-the-re-loop)) — dynamic analysis *confirms* the hypothesis that static analysis ([`pare-static-mcp`](https://github.com/EdibleTuber/pare-static-mcp)) formed, rather than re-discovering it:

- **Verify (observe)** — `java_hook` installs an observing hook and `read_hook_events` reads what it captured after the operator triggers the in-app action. An empty read means "not triggered yet," **not** a dead-end — trigger and read again.
- **Verify (compute)** — `execute_script` runs pure JS in a bare QuickJS sandbox (no Java bridge) for offline byte math / decoding; the script's completion value comes back as `value`, so a `transform(candidate) == target` check needs no device round-trip.

When Verify surfaces something static didn't predict (a runtime-only class, a native call), that is a lead back to static — PARE **Re-orients**. PARE is the hub that drives these tools and carries the loop — see [PARE](https://github.com/EdibleTuber/PARE).

## Status

Android v1: device/process discovery, attach, script load + ad-hoc eval, the
message pump + SQLite capture store, Java hooking (install + remove), and the
memory-inspection surface (enumerate / read / write). iOS, SSL/root/JB
bypasses, the script vault, and `scan_memory` are explicit fast-follows
(see `docs/superpowers/specs/2026-05-28-pare-frida-mcp-worker-design.md`).

### Known v1 limitations (tracked in spec §9)

- `PARE_FRIDA_MAX_DISK_PER_SESSION` is read but **not enforced** in v1 — the
  config variable exists for forward-compatibility, but `CaptureStore.write`
  does not yet refuse on quota exceedance. Set the quota generously and watch
  disk usage manually until enforcement lands.
- The message pump persists on explicit `flush()` (triggered by capture-read
  tool calls), not via a background timer; under a chatty hook between flushes,
  messages can hit the in-memory queue bound and get dropped (with a counter).
- Per-row SQLite commits in the pump are not yet batched — fine for v1
  validation traffic, would need batching under a real high-frequency hook.

## Install

```bash
pip install -e ".[dev]"
make agent     # compiles the bundled Frida agent (TS -> dist/agent.js)
```

The bundled `dist/agent.js` is committed, so `make agent` is only needed when
the TS source changes.

## Registering with PARE

Add this entry to `~/Projects/PARE/workers.yaml`:

```yaml
workers:
  frida:
    command: "pare-frida-mcp"
    transport: stdio
    risk_default: low
    capability_tags: [mobile, dynamic, android, frida]
```

### Per-tool HITL gating (PARE-side follow-up)

The worker declares per-tool `risk_tier` values in its `list_tools` metadata
(satisfying `agent_core`'s `assert_conformance`), but PARE's runtime
`RiskAwareToolPool` currently sources the declared tier from the worker-wide
`risk_default` + fnmatch override patterns. Once PARE parses a
`risk_overrides:` section in `workers.yaml`, escalate the dangerous tools:

```yaml
risk_overrides:
  - ["frida_write_memory", "high"]
  - ["frida_execute_script", "critical"]
```

Until that follow-up lands, this worker is gated only at the `risk_default`
floor — treat dangerous tools accordingly.

## Tests

```bash
make test                                  # unit + integration (no device)
pytest tests/device/                       # real-device flows (auto-skip without USB)
```

## Layout

- `src/pare_frida_mcp/` — Python package
  - `contract.py` — single source of tool metadata (`TOOL_SPECS`, tiers, schemas)
  - `server.py` — FastMCP stdio entry point
  - `tools.py` — handlers wired to `core/`, `android/`, the capture store
  - `core/`, `android/` — Frida orchestration (devices, sessions, scripts, memory, java hooks)
  - `capture/` — per-session SQLite store with promoted hot-field columns + FTS5
  - `agent/` — TS source for the in-target Frida agent (compiled to `dist/agent.js`)
- `docs/superpowers/` — design spec + implementation plan
