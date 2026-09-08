# Python hook capability cleanup (NHD-091–095)

Status: accepted for this cleanup slice. The machine-readable ownership
contract is `docs/guard/contracts/python-capability-ownership.v1.json`, and
the always-selected Rust authority workflow runs
`scripts/ci/python_capability_cleanup_gate.py`.

## Ownership result

The inventory covers 82 hook/runtime Python files. Every scoped file has one
and only one owner:

| Class | Files | Responsibility |
|---|---:|---|
| Required control plane | 64 | adapters, byte transport, native launch, supervision, presentation, and non-authoritative receipts |
| Named reference oracle | 17 | explicit differential tests and the documented pure-Python rollback oracle |
| Dead duplicate | 1 | superseded Python resident transport |

The Rust runtime remains the sole semantic authority for supported native hook
decisions. Python control and transport code may authenticate, launch,
project, render, and persist bounded evidence, but cannot create a production
semantic fallback.

## Reachability proof

`commands_support` and `commands_hook` no longer import the legacy hook
evaluators eagerly. The compatibility modules are loaded by
`commands_hook_compat_loader.py` only when all of the following are true:

1. the Python oracle flag is explicitly enabled;
2. test mode (or pytest's test marker) is present; and
3. the selected native mode is `off` or an explicitly diagnostic `shadow`.

Direct imports of legacy modules remain available to named regression tests
through the test-only namespace bootstrap. A clean subprocess import of the
production CLI facade proves that the legacy evaluator modules and the
retired resident module are absent from `sys.modules`. The AST graph check
also proves that no source module imports the retired resident module.

Every `importlib.import_module` call is inspected by the cleanup gate,
including aliases imported directly from `importlib`. A destination must be a
bounded literal/static expression, a value from a bounded literal loop, or a
same-module helper call whose callsites are all statically bounded. Empty,
oversized, malformed, and caller-controlled destinations fail the gate; the
aggregate report records the check and any unbounded locations without
recording destination values.

## Retained deletion candidate

`src/codex_plugin_scanner/guard/native_runtime_resident.py` is the only
dead-duplicate candidate. Rust owns the resident protocol, admission,
supervision, framing, and lifecycle. The Python source remains in the tree so
this change does not delete files or history, but Hatch excludes it from wheel
and sdist output. Removing the source itself requires a separate deletion
review; the exact path and reason are recorded in the v1 contract.

## Fixture and package evidence

`tests/fixtures/native-hook-parity/cases.v1.json` contains six
language-neutral PreToolUse/PostToolUse envelope classes and expected action
floors. It carries no commands, paths, prompts, content, secrets, or
implementation-specific fields. The cleanup gate validates its schema and
digest, confirms the named oracle suites exist, and checks that a wheel cannot
contain the excluded resident module. The retained oracle is explicitly
exercised by `tests/test_python_capability_cleanup_gate.py` and the existing
semantic/reference suites.

## Delta and rollback boundary

The gate's snapshot at this change is:

| Surface | LOC |
|---|---:|
| Required control plane | 16,336 |
| Named reference oracle | 6,619 |
| Evidence persistence | included in control plane; 762 LOC subset |
| Retained dead candidate | 569 |

No project dependency, public script, or runtime flag was removed: no safe
candidate could be proven dead without widening the rollback boundary. The
package exclusion is the only packaging delta. Reverting the lazy loader and
the single Hatch exclusion restores the previous import/package surface; any
source deletion or oracle removal remains a separately reviewed change.

## Verification

```text
uv run --no-sync ruff check <changed Python files>
uv run --no-sync pytest -q tests/test_python_capability_cleanup_gate.py
uv run --no-sync pytest -q tests/test_python_hook_semantic_callgraph_gate.py tests/test_guard_hook_payload_reference.py
uv run --no-sync python scripts/ci/python_capability_cleanup_gate.py --root . --json python-capability-cleanup.json
```

Windows CI is intentionally outside this cleanup slice; the native
cross-platform gates remain owned by their existing workflows.
