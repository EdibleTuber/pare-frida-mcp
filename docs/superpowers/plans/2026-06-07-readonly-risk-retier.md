# Read-only frida re-tier Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make frida's read-only metadata/capture tools auto-execute (no operator prompt) by lowering PARE's `frida` risk floor to `low` and re-tiering the two tools that must still prompt (`read_memory`, `java_hook`) up to `high`.

**Architecture:** The risk system is escalate-only (`resolve_declared_tier = max(floor, advertised)`; `RiskGate` overrides up only) and the approval gate fires only on `high`/`critical`. So ungating reads is done by dropping the worker floor (in `PARE/workers.yaml`) so each tool's honestly-advertised tier (in `pare-frida-mcp/contract.py`) governs — and bumping `read_memory`/`java_hook` to `high` so they stay gated once `medium` no longer prompts.

**Tech Stack:** Python, pytest (run via `/home/edible/Projects/PARE/.venv/bin/python`, which has both `pare_frida_mcp` — editable-installed — and `agent_core`).

**Cross-repo note:** This one change spans two repos. `pare_frida_mcp` is editable-installed in PARE's venv, so `contract.py` edits are live immediately — no reinstall, and the PARE test in Task 2 sees the new tiers as soon as Task 1 lands. Do Task 1 before Task 2.

**Spec:** `docs/superpowers/specs/2026-06-07-readonly-risk-retier-design.md`

---

## File Structure

- `pare-frida-mcp/src/pare_frida_mcp/contract.py` — **modify**: `read_memory` and `java_hook` `ToolSpec` tier `medium → high` (lines 55, 61).
- `pare-frida-mcp/tests/unit/test_contract.py` — **modify**: assert the two new tiers.
- `PARE/workers.yaml` — **modify**: `workers.frida.risk_default: high → low` (line 20).
- `PARE/tests/test_risk_overrides_coverage.py` — **modify**: assert the floor is `low` and that tools resolve to the intended gated/non-gated tiers under it.

---

## Task 0: Branches + commit the design docs

**Files:** none (git only). The two specs and this plan are currently untracked in the `pare-frida-mcp` working tree on an unrelated branch.

- [ ] **Step 1: Branch `pare-frida-mcp` off main and bring the docs along**

```bash
cd /home/edible/Projects/pare-frida-mcp
git stash --include-untracked   # park the untracked docs if the tree is mid-other-work
git checkout main
git checkout -b feat/readonly-risk-retier
git stash pop                    # restore the docs onto the new branch
git add docs/superpowers/specs/2026-06-07-readonly-risk-retier-design.md \
        docs/superpowers/specs/2026-06-07-snapshot-viewer-command-design.md \
        docs/superpowers/plans/2026-06-07-readonly-risk-retier.md
git commit -m "docs: read-only risk re-tier + snapshot viewer specs and re-tier plan"
```

- [ ] **Step 2: Branch `PARE` off main**

```bash
cd /home/edible/Projects/PARE
git checkout main && git checkout -b feat/frida-floor-low
```

---

## Task 1: Re-tier `read_memory` and `java_hook` to `high` (pare-frida-mcp)

**Files:**
- Modify: `src/pare_frida_mcp/contract.py:55` (`java_hook`), `:61` (`read_memory`)
- Test: `tests/unit/test_contract.py`

- [ ] **Step 1: Write the failing test**

Add to `tests/unit/test_contract.py`:

```python
def test_read_memory_and_java_hook_are_high():
    by_name = {s.name: s for s in TOOL_SPECS}
    assert by_name["read_memory"].risk_tier == "high"
    assert by_name["java_hook"].risk_tier == "high"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd /home/edible/Projects/pare-frida-mcp && /home/edible/Projects/PARE/.venv/bin/python -m pytest tests/unit/test_contract.py::test_read_memory_and_java_hook_are_high -v`
Expected: FAIL — `assert 'medium' == 'high'`.

- [ ] **Step 3: Edit the two ToolSpec tiers**

In `src/pare_frida_mcp/contract.py`, change the tier string (second positional arg) from `"medium"` to `"high"` on these two lines only:

```python
    ToolSpec("java_hook", "high", "Install an observing Java method hook.",
```
```python
    ToolSpec("read_memory", "high", "Read target memory (hex preview).",
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `/home/edible/Projects/PARE/.venv/bin/python -m pytest tests/unit/test_contract.py -v`
Expected: PASS (all contract tests, including the new one).

- [ ] **Step 5: Run the wire-tier integration test (no regressions)**

Run: `/home/edible/Projects/PARE/.venv/bin/python -m pytest tests/integration/test_wire_risk_tier.py -q`
Expected: PASS. (It asserts each advertised tier reaches the wire; the two changed tiers flow through unchanged in shape.)

- [ ] **Step 6: Commit**

```bash
git add src/pare_frida_mcp/contract.py tests/unit/test_contract.py
git commit -m "feat(contract): read_memory and java_hook advertise high (prompt-gated)"
```

---

## Task 2: Lower the frida floor to `low` (PARE)

**Files:**
- Modify: `workers.yaml:20` (`frida.risk_default`)
- Test: `tests/test_risk_overrides_coverage.py`

- [ ] **Step 1: Write the failing tests**

Add to `PARE/tests/test_risk_overrides_coverage.py` (it already imports `WorkerRegistry`, `resolve_declared_tier`, and `pare_frida_mcp.contract`; if an import is missing, add `from agent_core.workers.risk import resolve_declared_tier`):

```python
def test_frida_floor_is_low():
    reg = WorkerRegistry.load("workers.yaml")
    assert reg.get("frida").risk_default == "low"


def test_readonly_frida_tools_auto_execute_under_low_floor():
    """With floor=low and honest advertised tiers, metadata/capture reads
    resolve to a non-gated tier; live-memory / behavior-altering tools gate."""
    reg = WorkerRegistry.load("workers.yaml")
    spec = reg.get("frida")
    import pare_frida_mcp.contract as contract
    advertised = {s.name: s.risk_tier for s in contract.TOOL_SPECS}

    def declared(tool):
        return resolve_declared_tier(spec, advertised[tool])[0]

    # Gate fires only on high/critical (risk_pool). These must NOT gate:
    for tool in ("enumerate_processes", "enumerate_applications",
                 "enumerate_modules", "enumerate_exports",
                 "search_capture", "read_capture",
                 "list_devices", "select_device",
                 "java_hook_remove", "attach", "load_script"):
        assert declared(tool) in ("low", "medium"), f"{tool} should auto-execute"

    # These MUST gate:
    for tool in ("read_memory", "java_hook", "write_memory"):
        assert declared(tool) == "high", f"{tool} should be gated"
    assert declared("execute_script") == "critical"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /home/edible/Projects/PARE && /home/edible/Projects/PARE/.venv/bin/python -m pytest tests/test_risk_overrides_coverage.py -k "floor_is_low or auto_execute" -v`
Expected: FAIL — `test_frida_floor_is_low` asserts `'high' == 'low'`; `test_readonly_..._under_low_floor` fails because under the current `high` floor `declared("enumerate_processes")` resolves to `"high"`, not `low`/`medium`.

- [ ] **Step 3: Lower the floor**

In `PARE/workers.yaml`, line 20, change:

```yaml
    risk_default: high          # FLOOR during rollout — lower to medium only after the e2e gate is green
```

to:

```yaml
    risk_default: low           # advertised per-tool tiers govern; reads auto-execute, dangerous tools gate (read_memory/java_hook/write_memory=high, execute_script=critical)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `/home/edible/Projects/PARE/.venv/bin/python -m pytest tests/test_risk_overrides_coverage.py -v`
Expected: PASS (the two new tests plus the existing pin-coverage tests, which pass `declared_tier="low"` directly and are floor-independent).

- [ ] **Step 5: Run the full PARE risk suite (no regressions)**

Run: `/home/edible/Projects/PARE/.venv/bin/python -m pytest tests/test_risk_overrides_coverage.py tests/test_risk_overrides_wired.py tests/test_pin_coverage.py tests/test_frida_wire_tier_e2e.py -q`
Expected: PASS. (The pin and e2e tests already operate at `declared_tier="low"` / explicit `risk_default="low"`, so the real-yaml floor drop does not affect them.)

- [ ] **Step 6: Commit**

```bash
git add workers.yaml tests/test_risk_overrides_coverage.py
git commit -m "feat(risk): drop frida floor to low so read-only tools auto-execute"
```

---

## Self-Review

- **Spec coverage:** floor drop → Task 2 Step 3; `read_memory`/`java_hook` → `high` → Task 1; resulting gating table → asserted in Task 2 Step 1; conformance-rejects-missing-tier safety → already enforced by existing `test_every_tool_has_required_metadata` (Task 1 file) and build-time conformance, no new task needed. No gaps.
- **Placeholders:** none — every step has concrete code/commands/expected output.
- **Type consistency:** `resolve_declared_tier(spec, advertised)[0]` returns the tier string (matches its `(tier, source)` signature); `reg.get("frida").risk_default` and `TOOL_SPECS[*].risk_tier`/`.name` match the real APIs used elsewhere in these test files.
