# Approval invariant

Every command Guard pauses for review can be approved. The user always sees
**Allow once** and **Always allow**, and an approved command runs. Guard does
not second-guess the answer.

This is a product rule, not an implementation detail. Do not add a code path
that pauses a command without offering both choices, or that ignores an
approval the user has given.

## The rule

1. A review (`review` or `require-reapproval`) always offers Allow once and
   Always allow. That includes commands Guard cannot prove, commands that run
   outside the workspace sandbox, package installs and Guard-control commands.
2. Allow once lets the agent's retry of that command through. The retry is a
   new tool call, so the binding leaves out the per-attempt call id (`tool_call_id`
   for Pi and Oh My Pi, `tool_use_id` for Claude Code and Codex) while a session
   id is present, and keeps the command, working directory, session and policy.
3. Always allow is saved against the command's hash. Every part of Guard (the
   Rust resident, the Python daemon, the hook paths and the dashboard) honors
   it.
4. An approval ends only when:
   - the user removes it, or
   - the command's hash changes.

   An approval saved under the command hash survives a rule change, a new
   extension, a different reason code or a change of environment.

Requests queued by a release that predates retry bindings are the one
exception. They carry `retry_cannot_reuse_approval` and no exact-action
binding, so the card cannot offer Allow once for them. Let the agent retry the
command: the fresh request is queued under this rule and offers both choices.

`require-reapproval` means "ask again when the artifact changes", not "ask again
every time". A saved allow bound to the request's context token answers that
exact artifact whatever scope carried it (artifact, workspace, publisher or
harness), so the identical retry runs. A token whose hash differs is refused,
and that refusal is the fresh approval the policy asks for. For a package
request the workspace scope is the repository identity plus the dependency
graph, so a workspace allow also answers the identical install in a linked
worktree of the same repository.

Only terminal verdicts are excluded. `block`, `sandbox-required` and `allow`
are not reviews, so there is nothing to approve.

## What the hash covers

When Guard can prove what a command runs, the approval token is the strong
exact-action token. It binds the resolved program and file contents as well as
the command, and it also binds Guard's rule set and extensions. Editing the
script or changing those rules makes it a new command, so Guard asks once more
and both choices are offered again.

When Guard cannot prove it, for example an executable outside the workspace
roots, a helper-selecting Git config or a mutable script launcher, the token
falls back to `native-command-hash-v1`. That hash covers:

- harness
- tool name
- workspace
- working directory (the payload `cwd`, else the workspace)
- for a shell tool, the command text
- for any other tool, its whole input as it was sent, including a `command`
  field and any other field, even when the input is not an object (empty only
  when the tool takes none)

Changing any of these produces a new command, and Guard asks again.

## Where it is enforced

| Concern | Code |
| --- | --- |
| Token for every review, with command-hash fallback | `rust/crates/guard-runtime/src/native_exact_action_op/token.rs` (`approval_token`, `command_hash`) |
| Resident exact-action answer | `rust/crates/guard-runtime/src/native_exact_action_op.rs` (`decide`, `Fallback::CommandHash`) |
| Allow once retry binding, with no package exclusion | `rust/crates/guard-runtime/src/native_exact_action_op/binding.rs` and the `Reuse::Argv` fallback in `native_exact_action_op.rs` |
| Saved package allows reused under `require-reapproval`, any scope | `rust/crates/guard-runtime/src/package_policy_resolve_approvals.rs` (`is_durable_exact_artifact_approval`) |
| Saved allows on the direct hook path | `rust/crates/guard-runtime/src/hook_direct_saved_decision.rs` (`approvable`) |
| Approval scopes offered to the user | `rust/crates/guard-runtime/src/approval_scope_contract.rs` (`allow_is_non_overridable` excludes only non-review verdicts) |
| Saved allows on the Python daemon path | `src/codex_plugin_scanner/guard/daemon/hook_native_saved_approval.py` (`_native_review_is_approvable`) |
| Routing of a review-tier artifact verdict (queued for approval, never terminal unless the operator chose not to be asked) | `rust/crates/guard-runtime/src/hook_decision_artifact_review_route.rs` (`artifact_review_route`), executed by `src/codex_plugin_scanner/guard/cli/commands_hook_native_review.py` |
| Reuse of a saved approval on the artifact hook (claim, revalidate, settled). A saved allow is claimed before it is used, a claim that wins is always revalidated against the request it was issued for, a claim that loses never allows, reuse reads no scope, so Always allow is honored whichever scope saved it and under `require-reapproval` (only a trusted browser request's override reads the source, and it claims a gate-written allow), and a changed hash is refused and never claimed | `rust/crates/guard-runtime/src/hook_decision_artifact_reuse_step.rs` (`artifact_reuse_step`), executed by `src/codex_plugin_scanner/guard/cli/commands_hook_native_reuse.py` (`execute_reuse_plan`); an unreachable resident falls to the host outage, or to `package_reuse_floor` for a package request |
| Choice of the handlers that answer a native hook (every review-capable event keeps a handler that offers both choices; only a devin or zcode permission request is handed to the harness prompt, and a route the resident cannot supply, or cannot supply within the harness's remaining budget, is the host outage response for every event, Claude permission dialogs and Stop included, never a verdict) | `rust/crates/guard-runtime/src/hook_decision_hook_route.rs` (`hook_route`), executed by `src/codex_plugin_scanner/guard/cli/commands_hook_native_route.py` and `commands_hook_native_route_handlers.py` |
| Gathering of local tool-grant evidence on a native tool request, and the receipt `approval_source` label (a label of who approved; it never narrows the choices offered) | `rust/crates/guard-runtime/src/hook_artifact_compose_policy_tail.rs` (`local_eligibility_required`, `approval_source`), read by `src/codex_plugin_scanner/guard/cli/commands_hook_native_policy_tail.py` |
| Review card choices | `dashboard/src/approval-retry-guidance.ts`, `dashboard/src/review-decision-card.tsx` |

## Regression tests

- `rust/crates/guard-runtime/src/native_exact_action_op/approval_fallback_tests.rs`
- `rust/crates/guard-runtime/src/native_exact_action_op_tests.rs` (`a_windows_launch_falls_back_to_the_command_hash`)
- `rust/crates/guard-runtime/tests/fixtures/hook_direct_saved_decision_vectors.json` (`allow-guard-control`, `allow-package`)
- `rust/crates/guard-runtime/src/package_policy_resolve_op_tests.rs` (`a_saved_allow_of_any_scope_lets_the_identical_require_reapproval_retry_run`, `a_changed_artifact_is_reviewed_again_whatever_scope_saved_the_allow`)
- `tests/test_guard_package_workspace_approval.py` (`test_workspace_package_approval_is_reused_across_linked_worktrees_with_the_same_dependency_graph`)
- `tests/test_native_review_exact_action_always.py`
- `tests/test_native_exact_action_read_only_identity.py`
- `tests/test_native_exact_action_benign_offers.py`
- `tests/test_script_approval_reproduction.py`
- `tests/test_guard_approval_scope_contract.py`
- `rust/crates/guard-runtime/src/hook_decision_artifact_review_route_tests.rs` (`review_tier_verdicts_keep_allow_once_and_always_allow`)
- `tests/test_artifact_review_route_parity.py` (`test_review_tier_verdicts_keep_allow_once_and_always_allow`)
- `rust/crates/guard-runtime/src/hook_decision_artifact_reuse_step_tests.rs` (`allow_once_revalidates_the_request_it_was_issued_for`, `a_saved_allow_is_honored_at_any_scope`, `a_saved_package_allow_is_honored_under_require_reapproval`, `a_changed_hash_is_refused_and_never_claimed`, `a_lost_claim_never_allows`)
- `tests/test_artifact_reuse_step_parity.py` and `tests/test_artifact_reuse_step_executor.py` (`test_allow_once_revalidates_the_request_it_was_issued_for`, `test_a_saved_package_allow_is_honored_under_require_reapproval`, `test_the_scope_that_carried_a_saved_allow_never_reaches_the_resident`, `test_an_expired_or_changed_hash_is_refused_and_never_claimed`)
- `rust/crates/guard-runtime/src/hook_decision_hook_route_tests.rs` (`every_route_keeps_the_review_path_and_fails_closed`)
- `tests/test_hook_route_parity.py` (`test_the_pipeline_runs_the_recorded_effects`, `test_a_malformed_route_fails_closed`)
- `rust/crates/guard-runtime/src/hook_artifact_compose_policy_tail_tests.rs` (`review_tier_verdicts_keep_allow_once_and_always_allow`)
- `tests/test_policy_stack_tail_parity.py` (`test_the_resident_pins_the_receipt_approval_source`)
- `dashboard/src/approval-retry-ux.test.ts`, `dashboard/e2e/approval-scope-ui.spec.ts`

If one of these fails after a change, fix the change. Do not relax the test.
