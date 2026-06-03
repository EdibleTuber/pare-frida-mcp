# Tool-output policy (the north star)

**Status:** Standing design principle for the frida worker. Guides which tools
persist-then-search and which return inline.

PARE is driven by a local model whose scarcest resource is context. Every tool
result either spends context or is set up to be searched cheaply. This policy
defines the three shapes a tool result takes and where each one lives.

## The three shapes

1. **Control results** — small, one-shot values the model needs immediately:
   `attach` (session_id), `select_device`, `write_memory` ack, `java_hook` /
   `java_hook_remove` ack, `load_script`. **Return inline.** Persisting them
   would be pure overhead.

2. **Snapshots** — point-in-time *state views* with **replace** semantics (a
   stale view is simply wrong): `enumerate_processes`, `enumerate_applications`,
   and conceptually `list_devices`. **Persist to the `@snapshots` store**, return
   a tiny handle + `source` key; the model searches with `search_capture`. Built
   on `core/snapshots.py` (`SnapshotStore`, per-query replace, LRU).

3. **Streams / logs** — append-only history: hook events, `execute_script`
   output, script messages. **Persist to the per-session `CaptureStore`**
   (append semantics), searchable via `search_capture` / `read_capture`.

## The rule

> Any tool whose output is large enough to threaten context economy persists to
> the store that matches its data shape (replace → `@snapshots`, append →
> session `CaptureStore`), and the model retrieves targeted slices via
> `search_capture` / `read_capture`. Small control results stay inline.

Persist-then-search is **not** "everything goes to snapshot." The store is chosen
by data shape, and small results don't persist at all.

## The universal floor

Independent of which shape a tool uses, `_ok` / `_err` guarantee **valid JSON**:
an oversized payload returns a valid fallback envelope, never a byte-truncated
(corrupt) string. This protects every tool — including ones not yet converted to
persist-then-search — so the local driver never receives unparseable output.

The richer retrieval treatment (lean rows, spread sampling, `count_only`,
item-level fitting) lives in the `search_capture` path; tools that become store
consumers inherit it for free.

## Current state vs. target

| Tool | Shape | Today | Target |
|---|---|---|---|
| `enumerate_processes` / `enumerate_applications` | snapshot | `@snapshots` ✓ | done |
| `execute_script` output | stream | session store ✓ | done |
| hook events (`java_hook`) | stream | session store ✓ | done |
| `enumerate_modules` / `enumerate_exports` | snapshot-shaped state view | **inline (large lists)** | **convert to store consumers** (next effort) |
| `list_devices` | snapshot | inline (always tiny) | leave inline (YAGNI) |
| `attach`, `select_device`, `write_memory`, `java_hook(_remove)`, `load_script` | control | inline ✓ | leave inline |

The standout gap is `enumerate_modules` / `enumerate_exports`: snapshot-shaped but
still dumping large lists inline (the source of the `test_attach_enumerate_read`
corruption). Converting them is the next persist-then-search effort; until then
the `_ok` floor keeps their output valid.
