# Native hook oracle retirement

Status: implementation contract; not completion evidence.

This is the P1 continuation of the September 24, 2026 runtime migration program (RMN-008 and RMN-010 through RMN-014). The independent resident removal is PR #3095 / RMN-009. The remaining package, archive, native hook delivery, guarded-launch, and local MCP migrations are separate slices, not implied by completion here.

## Boundary

Rust already owns supported production hook decisions. Remove the old Python hook evaluator and its executable test oracle after replacing its useful behavioral coverage. Preserve Python daemon lifecycle, configuration, policy publication, non-authoritative receipts, and typed native-client projections. Preserve current host unavailability contracts and observation behavior; do not substitute a blanket allow or block for host-specific responses.

The initial source baseline is `07ed65432b812eb766443cecae64f34671d6236b` on PR #3095. This branch is stacked for review only. It must incorporate the final reviewed parent changes and target protected main before merge. Do not merge this branch into the parent implementation branch.

## Exact source retirement set

Delete these paths, not merely their packaging inclusions:

```text
src/codex_plugin_scanner/guard/cli/commands_hook_claude.py
src/codex_plugin_scanner/guard/cli/commands_hook_compat_bootstrap.py
src/codex_plugin_scanner/guard/cli/commands_hook_compat_loader.py
src/codex_plugin_scanner/guard/cli/commands_hook_compatibility.py
src/codex_plugin_scanner/guard/cli/commands_hook_copilot.py
src/codex_plugin_scanner/guard/cli/commands_hook_generic.py
src/codex_plugin_scanner/guard/cli/commands_hook_runtime_eval.py
src/codex_plugin_scanner/guard/cli/commands_hook_runtime_finish.py
src/codex_plugin_scanner/guard/cli/commands_hook_runtime_review.py
src/codex_plugin_scanner/guard/cli/commands_hook_runtime_state.py
src/codex_plugin_scanner/guard/cli/commands_hook_source_ref.py
src/codex_plugin_scanner/guard/runtime/hook_content_scanner.py
src/codex_plugin_scanner/guard/runtime/hook_decision_cache.py
src/codex_plugin_scanner/guard/runtime/hook_output_text.py
src/codex_plugin_scanner/guard/runtime/hook_payload_reference.py
src/codex_plugin_scanner/guard/runtime/hook_review_engine.py
src/codex_plugin_scanner/guard/runtime/hook_source_read.py
```

Extract only verified mechanical DTO/control functionality with live callers. Do not move an evaluator, source scanner, output walker, decision cache, or semantic interpreter into a new namespace. Keep `hook_review_types.py` and genuine enrichment-control services.

## Known dependencies to close

This is not a complete caller inventory. Expand it from the actual source before deletion.

* `tests/conftest.py` currently sets the default native mode to off and globally injects `HookReviewEngine` into `HookWorker._test_python_oracle_factory` and `commands_hook_source_ref._test_source_ref_oracle`. Retire that injection and oracle-only flags. Preserve unrelated native test support and daemon fixtures.
* `commands_hook.py` and `commands_support.py` retain compatibility loader exports and the old semantic command route. Remove those branches and their dynamic namespace integration. Keep supported public commands as bounded native delegation where necessary.
* `tests/guard_cli_facade_isolation.py` initializes legacy compatibility modules for monkeypatching. Port remaining control tests and retire the oracle bootstrap, rather than copying it into another test helper.
* `test_hook_review_engine.py`, `test_hook_review_observe_mode.py`, `test_hook_security_regressions.py`, and portions of `test_pi_extension_response_contract.py` exercise the old engine. Port their concrete behaviors into compiled native tests/fixtures, then delete the old implementation-specific nodes.
* The native differential and mutation differential suites import the old engine. Preserve the deterministic synthetic cases, including all three 64-case mutation seeds, but replace the live oracle with reviewed contract expectations. Keep native execution and failure assertions. Historical comparison may run from an isolated pinned worktree outside the final source tree.
* Audit source-reference, output, content scanner, decision cache, daemon request, CLI facade, SLO contract, packaging, capability cleanup, and semantic-callgraph tests for additional imports, constants and implementation assertions. Do not treat this list as proof of absence.

## Behavioral proof

Record exact old node IDs and the native test or fixture covering each behavior in the existing `runtime-retirement-ledger.v1.json`. Extend its schema/validator only where needed to distinguish retired behavior from obsolete implementation assertions. Do not start a parallel deletion ledger.

Retain and strengthen cases for clean and secret-bearing output, nested/structured output traversal and bounds, source references, exact content digest and character count, path escapes and symlinks, changed/replaced files, cache identity, policy changes, expiration, unavailable authority, deadlines, observation, host response directives, and approval identity.

Use inert synthetic fixtures. Do not capture production commands, credentials, private paths, prompts, or output. Do not store generated live-looking secrets if fixtures can construct them from components. Do not freeze a known incorrect legacy result as a mandatory behavior.

Python tests invoking the real compiled runtime remain valid integration tests. A replacement Python implementation, test-only evaluator, or algorithmic oracle does not.

## Permanent absence enforcement

Move all retired modules from retained-oracle classification to retired ownership in the existing capability manifest. Extend source, dynamic-import, recognizable-copy, artifact and old-test-node absence checks. Keep negative controls for renames, new paths, test-only copies, unbounded imports, stale node references and disabled ledger validation.

Remove the `HOL_GUARD_PYTHON_ORACLE` route and oracle-specific factory/flag/bootstrap handling after closing their callers. Preserve useful test-mode or diagnostic behavior unrelated to a Python evaluator. Explicit native off/unavailable behavior must not revive Python semantics.

## Acceptance

- All 17 exact source paths and their semantic copies are absent.
- No production or test import, lazy loader, public facade, generated launcher, package inclusion, or environment selector can execute the old evaluator.
- Every removed behavior has an explicit native destination or a reviewed obsolete-implementation rationale. No adversarial case is deleted merely because Rust fails it.
- Native and retained-control suites pass, including the actual native differential replacement corpus and host/source-reference tests.
- Existing Rust, Python lint/type, command freshness, privacy, authority, semantic callgraph, I/O ownership, cleanup, packaging and installed-product gates remain enabled.
- Canonical command generation runs after every Rust source change, then the compiler is rebuilt and freshness checked. Package and repository generated outputs agree.
- Built wheel and source distribution contain none of the retired source or bootstraps. Installed daemon/native-client and supported host-route tests run without the Python oracle.
- Current-head review findings are fixed and required independent approvals and CI are satisfied before main merge. No review/protection bypass.

## Completion evidence

Replace the initial status only after verification. Record exact final source/tree, parent PR incorporation, deleted source and test nodes, test mapping, retained Python responsibilities, local and CI commands/results, built artifact identity, platform limitations, and any unresolved dependency. P1 completion does not imply P2-P8 completion or a measured performance improvement.
