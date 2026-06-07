# Read-only frida tools auto-execute: floor drop + honest re-tier

**Date:** 2026-06-07
**Status:** Approved design (awaiting spec review)
**Spans:** `pare-frida-mcp` (`contract.py` advertised tiers) + `PARE` (`workers.yaml`
floor).
**Paired with:** `2026-06-07-snapshot-viewer-command-design.md` (`page_capture`
depends on this to auto-execute).

## Problem

PARE floors the frida worker at `risk_default: high` (`workers.yaml:20`), an
intentional **rollout floor** ("lower to medium only after the e2e gate is green").
The floor makes `resolve_declared_tier = max(floor, advertised)` resolve *every*
frida tool to `high`, so even pure reads prompt for operator approval. The
motivating transcript shows `search_capture` prompting **five** times and one
"list the apps" request costing **six** approvals — pure friction on read-only
metadata.

**Why "add an override" can't fix it.** The risk system is **escalate-only**:
`RiskGate.evaluate` is "override-up only — don't downgrade" (`risk.py`), and the
floor is a `max()`. So there is no override that lowers a read tool *below* the
`high` floor. (`list_tools` isn't ungated by an override — it isn't a gated dispatch
at all.) The only lever is the **floor** itself.

## Key facts

- Gate threshold is **`high`/`critical` only** (`risk_pool.py:89`) — `low` and
  `medium` auto-execute (audited).
- `contract.py` already advertises sensible per-tool tiers; the `high` floor masks
  them.
- Missing/invalid advertised tiers are rejected at **build-time conformance**, so a
  low floor does **not** fail-open for a future tool that forgets to declare a tier.

## Design

Two honest moves — lower the floor so advertised tiers govern, and bump the two
tools that must still prompt up to where the gate actually catches them (`high`),
since `medium` no longer prompts.

### 1. Lower the floor (PARE `workers.yaml`)

`workers.frida.risk_default: high → low`. Each tool's effective tier becomes its
advertised tier.

### 2. Re-tier two tools up (`contract.py`)

| Tool | Now | New | Why |
|---|---|---|---|
| `read_memory` | medium | **high** | reads live process memory — can scrape secrets; deserves a prompt |
| `java_hook` | medium | **high** | installs instrumentation that alters process behavior |

All other advertised tiers stay as-is.

### Resulting gating

| Auto-execute (audited, no prompt) | Prompt (approval) |
|---|---|
| `list_devices`, `select_device` (low) | `read_memory` (high ⬆) |
| `enumerate_processes/applications/modules/exports` (low) | `java_hook` (high ⬆) |
| `search_capture`, `read_capture`, `page_capture` (low) | `write_memory` (high) |
| `java_hook_remove` (low) | `execute_script` (critical) |
| `attach`, `load_script` (medium — routine session setup) | |

Rationale for the line: pure metadata/capture reads and routine session setup
(`attach`/`load_script`) auto-execute; anything that reads live memory, alters the
target, or runs arbitrary code prompts. This is the "lower the floor after the gate
is green" step the rollout comment anticipated, made safe by keeping the genuinely
dangerous operations at `high`/`critical`.

## What changes

- `PARE/workers.yaml` — `frida.risk_default: low`.
- `pare-frida-mcp/contract.py` — `read_memory` and `java_hook` → `"high"`.

## Testing

- **Conformance / tier resolution** (extend existing `list_tools`/risk-tier tests):
  under `risk_default: low`, assert effective tiers — `enumerate_*`,
  `search_capture`, `read_capture`, `page_capture`, `list_devices`, `select_device`,
  `java_hook_remove`, `attach`, `load_script` resolve to a **non-gated** tier
  (`low`/`medium`); `read_memory`, `java_hook`, `write_memory` resolve to `high`,
  `execute_script` to `critical` (all **gated**).
- Assert a tool advertising no/invalid tier is still rejected at build-time
  conformance (the low floor does not fail-open).

## Out of scope

- Lowering `write_memory`/`execute_script` — they stay gated by design.
- Per-session or per-target risk policy (a larger PARE concern).
- The `@snapshots` `/snapshot` command itself (paired spec).
