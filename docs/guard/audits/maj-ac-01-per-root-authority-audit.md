# MAJ-AC-01: per-root authority audit

Audited at `423f4a46dd` (2026-10-27). Reproduce with
`python3 scripts/audit_python_verdict_sites.py`.

MAJ-AC-01 asks for something the migration report does not measure. The report
counts reachability and lines of Python; the acceptance criterion is about
authority: does any entry root still authorize an operation on a verdict Python
computed? A module can be large and reachable and hold no authority at all, and
a four-line helper can hold all of it. Counting either way answers the wrong
question.

This audit answers it directly. `scripts/audit_python_verdict_sites.py` walks
the package's syntax tree and reports every function that turns Python control
flow into one of the six enforced `GuardAction` strings — a `return "allow"`, an
assignment to a name the runtime reads as the verdict, a verdict-keyed entry in
a dictionary literal, or a call that passes one as the verdict argument. It
follows a conditional or boolean expression into both of its branches, resolves
module-level verdict constants so `return dict(_ALLOW)` is not invisible, and
reads the Python this package carries as embedded script templates, because the
bounded CLI hook client and the Cursor hook script are written out and run on
the hook path rather than imported.

## What the scan can and cannot see

It is a syntactic scan, so it is exhaustive over one shape and blind to others.
It finds every site where a `GuardAction` literal is produced in package source,
including inside the generated hook clients. It does not follow a verdict that
arrives as data — a string read from JSON, a value threaded through a `dict`
that never names it — and it cannot read a template that is not parseable
Python. One template is in that state today: Cline's hook script is a format
string with `{event_name!r}` interpolations and escaped braces. Its action
strings were read by hand and are all membership tests, not productions.
`docs/guard/audits/python-verdict-sites.json` records that template under
`unparsed_templates`, and `--check` fails if the set of unreadable templates
changes, so a second one cannot appear silently.

A site that composes a verdict out of data rather than literals would be missed.
That is the limit worth stating plainly: this scan narrows the search to a set
small enough to read, it does not prove the set is everything.

## What it found

Sixty-one functions across forty-four files, every one of them under
`src/codex_plugin_scanner/guard/`. Nothing outside the guard package produces a
verdict, so the console-script entry points (`hol-guard`, `hol-guard-eval`,
`hol-guard-secrets` and the `plugin-*` aliases) hold no authority of their own.

Twenty-five of the sixty-one can only ever produce a `block`, a `review` or a
`require-reapproval`. A Python-produced verdict that is stricter than the
resident's cannot authorize anything, and fail-closed behaviour when the
resident is unreachable is the design, so these were cleared as a class rather
than read one at a time. They are the fail-closed renderers, the review queues
and the protect-path blocks. `--check` compares the action set of each site, not
just its name, so one of them growing an `allow` is a failure rather than a
silent reclassification.

The remaining thirty-six can produce an `allow` or a `warn`, so each one was
read. Thirty-four hold no authority of their own, in these readings:

- **Renders the resident's verdict** — `native_local_cli_grant_response` acts
  only on the resident's `hook_local_cli_rule` answer and leaves the review
  standing when it cannot read one; `_tool_decision_after_runtime_allow` carries
  the native route's own `decision_policy_action`; `allow_tool_call` files the
  row for a call the route already allowed; `local_tool_grant_decision` refuses
  any reply that is not a resident allow; `_expected_policy_action` echoes the
  action the request carried. In the generated bounded client, `_hermes_policy`
  reads the decision out of the daemon response and `_to_native` allows only
  when it read `allow` or `warn`; `_permission_decision` and the Cursor tail's
  `_cursor_permission` map the resident's action into a harness vocabulary and
  refuse an action they do not recognise.
- **Decodes a signed or stored decision** — `_exact_action`,
  `normalize_remote_approval_decision` and `_normalize_action` map a signed
  one-time answer onto the enforced vocabulary. `local_cli_command_state` admits
  or rejects a configured value and chooses nothing.
- **Records what the user answered** — `resolve_interactive_decisions` and
  `_prompt_for_artifact` prompt only for artifacts the resident already marked
  for review and file the pick behind the approval gate;
  `native_saved_decision_response` replays a saved exact-action decision bound to
  the artifact hash, and only where the resident marked the review approvable;
  `temporary_mcp_grant_decision` and `_continuation` do the same for MCP grants
  and retry copy; `wait_for_grok_live_approval` reads resolved approval rows, and
  `apply_grok_pretool_approval_wait` and the generated client's
  `_rewrite_grok_decision` carry its answer; `apply_approval_resolution` applies
  the resident's own resolution plan; `pause_native_pre_tool_for_approval` blocks
  while a review is pending and allows only on a saved approval the store
  matched.
- **Labels rather than enforces** — the workspace scan findings carry a `warn`
  in a record field beside their severity and lifecycle state, which no hook
  reads; `_request_recommended_scope`'s string is a key into the row's
  `recommended_scope_by_action` table; `_install_recommendation` feeds
  `policy_recommendation.action` and `can_install`, both read only by the CLI
  report renderer.
- **Neither** — `_repair_command_activity_persistence_health` writes a probe row
  inside a savepoint and rolls it back, proving the evidence write path without
  evaluating policy. `_observe_payload` and the generated client's
  `_failure_payload` answer observation events, which report activity that has
  already finished, so their `allow` authorizes no tool action. The two Cursor
  `beforeShellExecution` routes pass a call through to Guard's own approval sink,
  which opens the request owner-only, checks its digest and re-authorizes the
  command there.

`grok_hook_response_from_guard`, recorded here in an earlier pass as a latent
allow-shaped fallthrough, now normalizes an action it does not recognise to the
review tier before rendering. An enforcement event then denies like the other
two renderings of its kind, a prompt blocks, an observe-only event renders
nothing, and a recording-only session renders allow because it records rather
than enforces. Nothing is left to tighten there.

## The findings

Two sites settled a verdict in Python that the resident did not give. Both are
closed. PR #6320 deleted the second, and its row is gone from the baseline. The
first now renders the resident's `review_settlement`, so its row reads
`renders-native`. They are written up below because how each was closed is the
useful part.

### `_script_free_watch`

`src/codex_plugin_scanner/guard/daemon/hook_native_package_review.py` settles a
package review in Python in one case the resident did not settle.

Its main path is clean: the resident plans the review (`package_review_plan`),
says whether a verdict may let the command continue at all (`may_allow`), and
evaluates the request artifact (`evaluate_package_request_artifact`, which is a
thin call onto `evaluate_package_request_native`). An `allow` verdict renders an
allow and a `block` renders a block.

`_script_free_watch` is the exception:

```python
def _script_free_watch(evaluation: PackageRequestEvaluation) -> bool:
    """Whether every package is watched only because no package code runs."""
    return (
        evaluation.decision == "monitor"
        and bool(evaluation.packages)
        and all(package.get("scriptFreeRegistryInstall") is True for package in evaluation.packages)
    )
```

The resident said `monitor`. Python reads the per-package
`scriptFreeRegistryInstall` flags and decides that a watch which holds only
because no package code runs may continue as an allow. Every fact in that
decision comes from Rust —
`supply_chain_package_eval/fallback_packages.rs` sets the flag, and it sets it
only where `script_free_registry_install` or `script_free_git_free_tree_install`
proved the install writes registry package files and nothing else — but the rule
that combines them into an allow exists nowhere else. `rg
script_free_watch rust/crates` finds nothing.

### The package-shim approval resume

`_run_guard_protect_command` in `guard/cli/commands_dispatch_local.py` does the
same thing at the `guard protect` root. After an approval wait resolves with no
blocking row, it re-runs the request through the resident. When the resident
comes back with `review` or `require-reapproval`, this path checks that the
package request and execution context are unchanged and then overwrites the
verdict:

```python
elif _package_shim_approval_matches_fresh_request(initial_payload, fresh_payload):
    fresh_verdict = fresh_payload.get("verdict")
    if isinstance(fresh_verdict, dict):
        fresh_verdict["action"] = "allow"
        fresh_verdict["blocking"] = False
    fresh_payload["policy_action"] = "allow"
```

The resident evaluated the fresh request and asked for review. Python concludes
that the approval the user already gave covers it, because the request bytes
match. That is an authority rule, and it lives only here.

Neither was an open door: the first admits an install the resident already proved
runs no package code and `may_allow` still gates it; the second needed a resolved
approval for a byte-identical request. Both are nonetheless the shape MAJ-AC-01
was written to catch.

**Fix for `_script_free_watch`:** have the resident carry the answer. The
resident's package evaluation now returns a `review_settlement` (`allow`,
`review`, `block` or `guide`, with its reason) that already folds in the
script-free watch, and `native_package_review_response` renders it the way it
renders `decision`. `_script_free_watch` is deleted.

**Fix for the protect resume: delete it.** This audit assumed the shim's inline
approval left no decision row for the resident to read, so the rewrite had to be
ported into the re-evaluation. A probe against a pinned runtime showed the
opposite. "Allow once" at the prompt resolves at artifact scope with no
remembered rule; `approval_resolution_plan_op.rs` maps that pair to
`persistence = "once"`, so `apply_approval_resolution` writes a real
approval-gate row with an expiry. `is_fresh_artifact_approval` in
`package_policy_resolve_approvals.rs` accepts exactly that row shape together
with the resolved request's `resolution_scope == "artifact"`, claims the one
shot, and the resident answers `allow` on the re-evaluation by itself. The
Python rewrite therefore only ever fired where the resident had already decided
to keep the install paused — it was residue that happened to be shaped like an
authority rule. PR #6320 removed the `elif` and
`_package_shim_approval_matches_fresh_request` outright and pinned the resident's
own allow with an integration test, so this root composes nothing today.

## Keeping it true

A point-in-time audit stops being evidence the moment someone adds a site.
`docs/guard/audits/python-verdict-sites.json` records the reading and the action
set for each of the sixty-one, plus the one template the scan cannot read, and
`scripts/audit_python_verdict_sites.py --check` fails when the package and the
baseline disagree — on a new site, a removed site, a changed action set, or a
change in which templates are unreadable. `tests/test_python_verdict_site_audit.py`
runs it. A new verdict site has to be read and recorded before it can land,
which is what MAJ-AC-01 asked for in the first place.
