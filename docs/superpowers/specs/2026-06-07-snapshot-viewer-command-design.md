# `/snapshot` — deterministic snapshot viewer (v0)

**Date:** 2026-06-07
**Status:** Approved design (v0, revised after skeptical-panel review; awaiting spec review)
**Spans:** `pare-frida-mcp` (worker tool) + `PARE` (command).
**Depends on:** `2026-06-07-readonly-risk-retier-design.md` (lowers the frida floor so a
`low`-advertised `page_capture` auto-executes).

## Problem

Persisted enumeration data reaches the user *only by being transcribed through the
LLM*: an enumerate tool persists rows to `@snapshots` and returns a tiny handle;
the model then `search_capture`s, the rows enter its context, and it re-types them
to the user. A real session showed all three failure modes at once — 21 apps
captured but **14 shown** ("first 14 captured"); **five** `search_capture` calls to
retrieve them (it led with the FTS `text=` path that breaks on dotted names); and
**six** approval prompts.

**What this feature is — and isn't.** Those failures happen on the *natural-language
chat path*, where the model answers. This feature does **not** change that path. It
adds a deterministic **operator verifier / escape hatch**: a `/snapshot` command
that reads `@snapshots` and renders rows itself — complete, exact, the LLM entirely
out of the loop — so when you suspect the model dropped or garbled rows, you can get
ground truth. Making the *natural-language* request render deterministically is a
later phase (see Out of scope). To partly close the "how would I know to use it" gap
*now*, the enumerate tools' returned summary advertises it (below).

This is **v0**: deterministic `/snapshot` over `@snapshots`, single-shot render, no
paging. (Paging arrives with the `/log` stream work, where large stores actually
exist — see Out of scope.)

## Placement

| Repo | What |
|---|---|
| **pare-frida-mcp** | new worker tool `page_capture` (complete read over the snapshot store) |
| **PARE** | `pare/commands/snapshot.py` command + table renderer |
| **agent_core** | nothing |

`pare/commands/` already registers domain commands (`Hello`, `Health`), so
`/snapshot` slots in beside them.

## Data flow & approval

```
/snapshot …  →  daemon handle_command  →  Snapshot command
            →  ctx.agent.tool_pool.call_tool("frida", "page_capture", {...})
            →  rows  →  render table  →  yield ResponseMessage(text=table)  →  CLI
```

No model turn (commands don't go through the model). The call goes through the
**risk-gated `tool_pool`** (not the bare pool) so it is **audited**; because
`page_capture` advertises `low` and the dependency spec lowers the floor, it
**auto-executes without a prompt**. (Earlier drafts used the bare `mcp_pool` to skip
gating — rejected: it loses the audit trail and sets a guardrail-free precedent for
any command to reach `critical` tools. The gated pool gives promptless + audited.)

## Worker tool — `page_capture`

The human-facing read: **complete, never sampled**. Scoped to `@snapshots` for v0.

```
page_capture(session_id, source=None, field=None, contains=None,
             list_sources=False) -> dict
```

- **`session_id`** — store handle (`@snapshots`), resolved by the existing
  `_resolve_store`.
- **Single-shot, complete, byte-honest.** Returns *all* rows for the source — but it
  must not silently overflow. The shared `_ok` envelope discards the whole payload
  over `max_tool_bytes` (default 4096) and returns an empty fallback — which would
  make the "complete verifier" show nothing. So `page_capture` is **exempt from the
  4096 model cap** (it is consumed by the command and rendered, never placed in model
  context) and uses a large budget sized for a bounded snapshot. If a snapshot still
  exceeds that budget, it returns as many **whole rows as fit** plus an **explicit**
  `shown`/`total` so the cap is *honest* ("showing 180 of 412 — narrow with a
  query"), never a silent drop. (`@snapshots` rows are tiny and bounded — a few
  hundred max, `max_keys=32` — so this fallback is a safety net, not the norm.)
- **`source=None` → latest** resolves via `SnapshotStore._keys` (already MRU-ordered)
  — the most recently *written* snapshot. **Not** `MAX(seq)`: `seq` is a reused rowid
  (no `AUTOINCREMENT`, `store.py:11`), so after a re-enumerate `MAX(seq)` can point at
  an *older* source. Empty store → a friendly "nothing captured yet".
- **Search is `LIKE` on `summary` only, never FTS.** FTS `text=` breaks on dotted
  names; `summary` holds the glance value (`identifier` for apps, `name` for the
  rest). **`payload` is excluded** — it's serialized JSON, so `LIKE` would match keys
  and punctuation (`contains='name'` hits the `"name":` key in every row) — false
  positives, the opposite of a verifier. To avoid silently re-tiering the
  model-facing `search_capture`, `page_capture` uses **its own field allowlist**
  (`{source, type, summary}`); the shared `_ALLOWED_FIELDS` is left unchanged. Factor
  the `field`+`contains`→`WHERE … LIKE` builder into a helper both tools call.
- **`list_sources=True`** → the catalog `[{source, count}]`
  (`GROUP BY source`) for `/snapshot list`.
- **Restricted to a non-spilling store.** A "complete" reader that SELECTs `payload`
  loses rows whose payload spilled to blob (`payload` nulled, data in `blob_ref`,
  `store.py:112`). `@snapshots` sets a huge spill threshold so this can't happen;
  `page_capture` asserts/document that it only serves non-spilling stores. (The `/log`
  follow-up over session streams, which *do* spill, must restore from `blob_ref` like
  `read_capture` — a reason streams are a separate design, not a free reuse.)
- **Advertised risk `low`** (read-only); auto-executes via the floor drop.

## Command UX — `/snapshot`

- **`/snapshot`** → the latest snapshot, rendered in full. The header names the
  resolved source (`apps · enumerate_applications:device=emulator-5554 · 21 rows`) so
  "latest" is always self-identifying.
- **`/snapshot list`** → catalog of source keys + counts. (Parse: an arg of exactly
  `list` is the catalog; anything else is a key.)
- **`/snapshot <key-substring> [query]`** → a specific snapshot, optionally filtered.
  Key is **substring-matched** (never type the full `enumerate_applications:device=…`);
  ambiguous substring → list the candidates. `query` filters on `summary` via `LIKE`.

No `next`/`previous`/cursor in v0 (single-shot render; the snapshot store is bounded).
If paging is ever needed it belongs in `ctx.conversation.overrides` (the per-channel
state pattern `/reasoning` uses), **not** on the singleton command instance — deferred
to the `/log` work where large stores justify it.

## Render

A plain table with **dynamic columns** from each row's payload dict — apps
(`identifier,name,pid`), modules (`name,base,size`), exports (`name,address`) all
render with no per-tool code. **Width:** the command yields a string over a socket and
cannot spawn a pager or see the user's TTY, so the renderer **clips columns to a
conservative width (~100 cols)** — truncating long paths/symbols with an ellipsis —
rather than letting rows hard-wrap into garbage. Footer carries the true `total` (and
`shown` if the byte-safety cap engaged).

## Discoverability hook (cheap, ships with v0)

The enumerate tools already return a summary string. Append the pointer:
`"21 applications captured to @snapshots — run /snapshot to view all."` One line in the
existing return, no agent_core work, and it surfaces the escape hatch exactly where the
truncation happens.

## Error handling

- Unknown/empty key → `no snapshot matches '<x>' — try /snapshot list`.
- Ambiguous substring → list the matching keys.
- Empty search result → `0 of <N> rows match '<query>'`.
- Nothing captured yet (bare `/snapshot`, empty store) → route to the (empty)
  `/snapshot list` message, not an error.
- Worker error → a one-line message, not a stack trace.

## Testing

- **Worker (`page_capture`)** — seed a `CaptureStore` directly (no device): complete
  unsampled rows for a source; `source=None` resolves to the MRU source (and survives a
  `replace()` that renumbers seqs — assert it does *not* follow `MAX(seq)`); `LIKE`
  matches on `summary`; `payload`/unknown fields rejected by the tool's allowlist;
  `list_sources` catalog + counts; the byte-safety cap returns whole rows with honest
  `shown`/`total` (never a torn row, never silent zero).
- **Command (PARE)** — fake `ctx.agent.tool_pool`: dynamic-column render for
  app/module/export shapes; width clipping of long values; substring key match +
  ambiguous listing; `list`; `query` filter; bare→latest with self-identifying header;
  empty-store and empty-search messages.

## Out of scope / follow-ups

- **Natural-language trigger** (the real fix for the chat path): render a model-driven
  "show me the packages" deterministically. Needs a *generic* agent_core
  "display-destined" message so a model turn can route a render to the user without the
  rows entering its context — the one genuinely generic piece, and it belongs in
  agent_core.
- **`/log` over session streams** (hook events, `execute_script` output): a *different*
  read shape, not a free reuse of `page_capture` — session rows have no `summary`,
  high-cardinality `source` (`cls.method`), and **spill to blob**. This is where real
  paging (offset/cursor in `conversation.overrides`) and blob-restore land, with a real
  large-data driver.
- **Per-column / range search** (modules by `size`, `pid > N`): those fields live
  inside `payload` JSON, not columns (`_PROMOTE`), so it needs `json_extract` predicates
  or promoting fields to columns. No demonstrated need — deferred (YAGNI). `summary`
  name-search covers the present case.
- Per-shape pretty formatting (hex sizes/addresses, column ordering).
- The `/exit` alias gap (separate small fix).
