# Foundation hook/package configuration transport backport

This backports the reader/capture propagation from main commit
`b2f029900cd28a0c4cce6bd8c15f87511b7de8de` onto foundation base
`1cb1068056c8eeef5babc5f4f355481b37bc06e0`. The eight production changes are
limited to explicit optional keyword parameters, forwarded arguments, and their
supporting imports. The recorded AST comparison proves every other node remains
identical to the foundation base.

Both raw and normalized native attempts carry the exact reader and capture to
`HookWorker`. Compatibility hook refreshes, post-claim and post-wait preparation,
recursive evaluation, package policy reloads, and the active local approval queues
carry the same reader. Scope creation remains the caller's responsibility. Default
`None` behavior, decision logic, current-policy reload order, cache lifetime and
existing time budgets are preserved.

Seven CLI patches apply directly. Foundation's older package evaluator has no
whole-input snapshot wrapper or snapshot-error recovery branch. This backport
preserves that architecture and threads the reader through the existing helpers;
it does not import the newer snapshot feature or any native architecture.
The new test therefore omits the two main-only snapshot-error cases.

Light validation passed: Ruff and formatting for all 11 source/test files, and
all eight production AST comparisons. The rejected initial full-patch applicability
check is retained; no partial patch was applied by that check. Execution tests and
type checking are deliberately left to the parent's combined foundation gate once
all source dependencies are integrated. Main's passing test receipts are not
claimed as foundation execution evidence.

The focused test paths are:

- `tests/test_hook_package_config_reader.py` (eight parameterized cases);
- `tests/test_native_pretool_compatibility.py`;
- `tests/test_guard_hook_post_claim_freshness.py`.

`manifest.json` records the exact source and raw-output hashes. No main checkout
file was modified, and no benchmark, installed qualification or GitHub publication
was performed by this backport.
