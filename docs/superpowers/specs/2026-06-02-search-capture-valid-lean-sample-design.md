# search_capture: valid JSON, lean rows, count preview, spread sampling

**Date:** 2026-06-02
**Status:** Approved design

## Problem & motivation

PARE is driven by a local model whose scarcest resource is context. The
snapshot/capture stores exist so tools persist their full output and the model
pulls back only targeted slices via `search_capture`/`read_capture`
(persist-then-search). The device enumeration tools (just landed) are the first
feature to produce large snapshots the model routinely searches — and exercising
them on a real emulator exposed three problems in the search surface that
undermine the whole pattern:

1. **Truncation corrupts JSON.** Every handler returns
   `bound_text(json.dumps(payload), _CAP)`. `bound_text` truncates raw UTF-8
   bytes with no awareness of JSON structure (`bounding.py`), so any result that
   exceeds the 4096-byte cap comes back as **invalid JSON**. A broad search over
   a ~95-process snapshot trips this immediately (observed:
   `JSONDecodeError: Unterminated string ... char 4038`). The model receives
   unparseable output. (This is latent across the codebase — the session-store
   path hits it too — but enumeration makes it routine.)

2. **Rows are fat.** A search match is the full `messages` row:
   `seq, ts, type, source, hook, url, method, cls, ret, summary, payload,
   blob_ref`. For a snapshot row whose real data is `{"pid":1,"name":"init"}`,
   ~8 of those columns are `null` noise. The byte cap is consumed by dead columns,
   so it bites after only a handful of rows.

3. **No cheap way to gauge or sample a result set.** The model can't ask "how
   many would this match?" without paying for rows, and can't peek at a
   representative few to decide how to narrow.

The byte cap itself is not the problem — it is what *enforces* context economy
(without a bound, a sloppy broad search re-floods context, defeating the store).
The fix is to make the bound **degrade correctly** and to make the intended
targeted/sampled flow smooth.

## Design

A small, composable verb set on `search_capture`, all preserving context economy:

### 1. Valid JSON, always (item-level bounding)

Stop truncating serialized JSON. Instead, bound at the **item** level: build the
result with as many whole rows as fit the byte budget — accounting for the full
response envelope (`summary`, `total`, `returned`, `truncated`, `matches`) — and
drop whole rows from the end if needed. `matches` is always a structurally valid
list; the surrounding `_ok` envelope never needs string truncation. `bound_text`
remains only a last-ditch safety net that, in the intended flow, never fires.

A shared helper fits rows under a budget given a fixed envelope overhead and
returns `(fitted_rows, fully_fit: bool)`. At least one row is always returned
when any exist, so progress/visibility is guaranteed.

### 2. Lean rows (drop null/empty columns)

`search_capture` is shared with the session/stream store, where
`hook`/`url`/`method`/`cls`/`ret` are meaningful (hook events). So rather than a
snapshot-specific projection, each returned row **drops keys whose value is
`None` or `""`**:

```python
lean = {k: v for k, v in dict(row).items() if v not in (None, "")}
```

For a snapshot row this strips all the stream columns automatically (leaving
`seq`, `source`, `summary`, `payload`); for a hook row it keeps exactly the
fields that matter. Store-agnostic, no special-casing. `seq` is always present
(primary key) so the model can `read_capture(seq=…)` any row.

### 3. Count preview (`count_only`)

A new boolean input. When true, `search_capture` runs only the `COUNT(*)` and
returns `{total, summary}` with **no rows** — a near-zero-context probe so the
model can ask "how many match?" before spending context. (Note: `total` is
already returned on every normal search via an independent `COUNT(*)`, so a
normal search still reveals the true magnitude; `count_only` just skips the row
fetch entirely.)

### 4. Model-controlled `limit` (the peek knob)

`limit` is currently hardcoded to 50 inside `search.py` and not exposed. Expose
it as an input (`0` ⇒ default 50). This is what lets the model say "show me a
couple to see the flavor" (`limit=2`) and get a small sample plus the true total.

### 5. Spread sampling (not first-N)

When the match count exceeds `limit`, return a **spread** of `limit` rows evenly
distributed across the ordered result set — not the first `limit`. For a snapshot
(ordered by seq = sorted order), first-N gives a skewed taste
(`android.x, android.y, android.z`); a spread gives a representative one
(`com.android.settings, com.google.maps, org.user.app`), which is what makes the
"what flavor of results am I getting?" peek actually informative.

Algorithm: with `total = N` and a requested `limit = L`:
- if `N <= L`: return all matches in seq order (no sampling needed);
- else: select `L` rows at evenly spaced positions across the `N` ordered
  matches (e.g. a `ROW_NUMBER() OVER (ORDER BY seq)` window with a stride of
  `N // L`, or equivalently compute `L` spread indices and fetch those rows).
  Deterministic.

Byte-level item bounding (step 1) is applied *after* sampling; if the spread
still exceeds the budget, whole rows are dropped from the end (the result stays a
spread of the lower portion). `returned`/`truncated` reflect the final set.

### 6. Truncation is impossible to miss (narrow guidance)

The model must always know when it's seeing a partial/sampled view, prose-first
(a weak local driver may skim past a JSON flag):

- **`summary` (load-bearing):** true `total` first, then what's shown and the
  next action. Examples:
  - normal full: `"12 matches"`
  - sampled/truncated: `"95 matches — showing a 12-row spread sample. Narrow with a more specific text=, or read_capture(seq=…) for one record."`
  - count only: `"95 matches (count only). Add text= terms to narrow, or search again without count_only to sample."`
- **structural counts:** `total` (accurate, independent of returned) vs
  `returned`. The gap signals incompleteness even if prose is ignored. `total`
  is never derived from the returned rows, so truncation **never hides the true
  magnitude**.
- **`truncated: true`** boolean for programmatic handling.

The guidance is **narrow-only**: no `offset`/paging. The model tightens its query
or samples; `read_capture(seq=…)` already covers pulling one record in full.

## What changes

- `src/pare_frida_mcp/capture/search.py` — replace the
  `bound_text(json.dumps(matches))`-then-halve logic with: lean rows; spread
  sampling when `total > limit`; item-level fitting under `byte_budget` that
  accounts for the envelope; always-valid `matches`; accurate `total`. Add a
  `count_only` path (COUNT only, no rows). Accept an effective `limit`.
- `src/pare_frida_mcp/bounding.py` — add a small item-fitting helper
  (`fit_items(rows, byte_budget, reserve)` → `(rows_that_fit, fully_fit)`), the
  valid-JSON analogue of the removed `page_items` but envelope-aware and
  offset-free.
- `src/pare_frida_mcp/tools.py` — `search_capture` handler: pass through new
  `limit` and `count_only` inputs; build the prose `summary` with narrow/sample
  guidance; assemble `_ok` from the pre-fitted rows (no reliance on `bound_text`
  to bound).
- `src/pare_frida_mcp/contract.py` — extend `search_capture` `input_schema` with
  `limit` (integer) and `count_only` (boolean); update its description to mention
  count-only and sampling. risk_tier stays `low`. No new tool.

## Testing

- **Unit — valid JSON (regression for the bug):** a store with many/large rows;
  `search_capture` over budget returns a result that `json.loads` cleanly;
  `matches` is a valid list; `truncated is True`; `total` is the full count.
- **Unit — lean rows:** a snapshot row returns only non-null keys (no
  `hook`/`url`/`method`/`cls`/`ret`/`blob_ref`/`ts`/`type`); `seq`, `source`,
  `summary`, `payload` present. A hook/stream row still returns its meaningful
  columns.
- **Unit — count_only:** returns `total` with no rows (no `matches`, or empty),
  and does not run the row query.
- **Unit — limit peek:** `limit=2` returns 2 rows and the accurate full `total`.
- **Unit — spread sampling:** `total=100, limit=5` returns 5 rows whose seqs are
  spread across the range (gaps > 1; not the first five consecutive), and
  includes near-first and near-last positions. `total <= limit` returns all in
  order with `truncated False`.
- **Unit — accurate total always:** `total` independent of `returned`/budget.
- **Unit — handler:** `search_capture("@snapshots", count_only=True)` and
  `search_capture("@snapshots", limit=2)` route to the snapshot store; summary
  text contains the magnitude and the narrow/sample guidance; result is valid
  JSON. A normal `session_id` path still flushes and searches unchanged.
- **Regression:** existing `search_capture`/`read_capture` session tests pass
  (the lean-row drop must not remove fields those tests rely on; adjust only if a
  test asserted a column that is legitimately null).

## Out of scope

- `read_capture` / `enumerate_modules` / `enumerate_exports` inline-list
  truncation: they share the same `_ok`/`bound_text` corruption pattern and can
  reuse the new `fit_items` helper, but converting them is separate work (and
  `enumerate_modules`/`exports` are slated to become snapshot consumers later).
- `offset`/paging through a full result set (deliberately narrow-only).
- Changing the byte cap value or making it configurable per call beyond the
  existing `byte_budget` input.
- Random (non-deterministic) sampling — the spread is positional/deterministic.
