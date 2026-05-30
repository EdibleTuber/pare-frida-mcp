# pare-frida-mcp

A Python FastMCP stdio worker that gives the PARE reverse-engineering agent
Frida 17 dynamic-instrumentation tools for Android (v1).

## Status

Android v1: device/process discovery, attach, script load + ad-hoc eval, the
message pump + SQLite capture store, Java hooking, and the full
memory-inspection surface (enumerate / read / scan / write). iOS, SSL/root/JB
bypasses, and the script vault are explicit fast-follows
(see `docs/superpowers/specs/2026-05-28-pare-frida-mcp-worker-design.md`).

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
