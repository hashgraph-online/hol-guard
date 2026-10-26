# Every prompt blocked with `native_policy_not_ready`

Status: fixed, pending release
First reported: 2026-10-21
Fix: `#5658`

## What people saw

Every prompt in an affected harness was refused before review:

```
Warning: HOL Guard could not prepare protection for this prompt.
Retry the prompt to reconnect (native_policy_not_ready).
```

Retrying never helped. Updating to the latest release did not help either,
because the first attempted fix did not address the cause.

## The failure

`prepare_native_hook_policy` is the last gate before a prompt is reviewed
(`src/codex_plugin_scanner/guard/daemon/hook_policy_admission.py`). When
`HookWorker.prepare_workspace_policy` returns `None`, it writes the
`native_policy_not_ready` fail-safe and the prompt never reaches Guard. So the
whole incident reduces to one question: why did the worker hold no policy?

Three things lined up.

**1. The guard home's command catalog drifted from the installed runtime.**
A guard home records the command program named by its activated catalog. The
runtime binary carries its own `PACKAGED_COMMAND_PROGRAM_ID`. On an affected
home, a committed activation named a program no installed runtime builds.
`_stamp_runtime_program_digest`
(`native_policy_snapshot_publisher_transport.py`) deliberately declines to
overwrite `program_digest` when the catalog and trust digests do not match the
runtime, so every push shipped the stale program.

**2. The resident refused the whole snapshot over the command binding.**
Command-extension admission failures are refusals of one optional part of the
snapshot, but the publisher treated them as refusals of the snapshot. The
publisher raised, held nothing, and the worker had no policy to give the hook.
Enforcement was lost for a reason that had nothing to do with enforcement.

**3. The real error code never reached the publisher.**
`safe_error_response` (`rust/crates/guard-runtime/src/resident_protocol.rs`)
rewrites any error code outside its declared allow-lists into the literal
`native_request_invalid_json`. None of the command-admission codes were
declared, so the publisher — and every log and diagnostic built on it — saw a
JSON parse failure for a payload that parsed fine. The one piece of evidence
that pointed at the cause was being erased in transit.

Together: a drifted catalog made every push unacceptable, an unacceptable
binding sank the whole policy, and the masked code sent diagnosis in the wrong
direction.

## The fix

The catalog drift has to be repaired where it is recorded. `#5648` migrates the
installed command pack's activation at daemon startup: when the activated
engine no longer matches the installed one, `migrate_active`
(`src/codex_plugin_scanner/guard/catalog_delivery/installed_upgrade.py`)
finishes any anchored transition and prepares a candidate activation for the
engine the runtime actually ships, before any policy is prepared. A home that
has drifted stops producing a binding the runtime cannot admit.

`#5658` makes the next failure of this shape legible rather than repairing this
one. `safe_error_response` rewrites any code outside its declared vocabulary
into `native_request_invalid_json`, and the fifteen failures raised while
admitting a command binding were all undeclared. They are declared now, so the
publisher and every log built on it see the refusal the resident actually
raised. A resident test pins that those codes cross the boundary unchanged.

### What was tried and removed

An earlier shape of `#5658` had the publisher retry once without the command
binding when admission refused it. That cannot work, and it should not.

It cannot work because `next_floor`
(`rust/crates/guard-runtime/src/policy_store_command_floor.rs`) refuses any
snapshot that drops `command_extensions` once a protected command-control floor
exists, and that floor survives restarts. Every affected home reports
`health = protected`, so the retry is refused with
`native_command_control_binding_removed` before admission is reached. The
machine stays wedged.

It should not, because `with_command_loader` runs only when the binding is
present. A binding-less snapshot silently drops managed and signed-cloud
layers, `global_lockdown`, per-target controls, authority epochs and
`active_security_digest`. The retry would have lowered a policy floor without
approval in exchange for a recovery that never arrives.
`protected_floor_refuses_a_snapshot_that_drops_the_command_binding` pins the
refusal so this is not proposed again.

## Verification

`#5648`'s migration is reached on an affected home: its trigger is
`previous.engine != installed.engine`, and the home that reported this incident
had an activated engine that no installed runtime builds. Confirming that the
migration completes and the home un-wedges requires installing a build that
contains it on that machine and watching `prepare_workspace_policy` return a
policy. Until that is done, this is a diagnosis supported by the source, not an
accepted fix.

`#5658` is verified at the boundary it changes: the resident test shows the
admission codes reaching the publisher unchanged, and the floor test shows the
binding-less push refused both in-process and after a restart.

## Why the first attempt shipped broken

The earlier release was cut on evidence that looked complete and was not. The
gaps, in the order they mattered:

- **The reported symptom was never reproduced.** Work started from a hypothesis
  about the publisher and stayed there. Nothing in that first cycle ever called
  `prepare_workspace_policy` and watched it return `None`, which is the only
  thing that produces the message people saw.
- **A component probe was accepted as a system proof.** "The publisher recovers"
  and "the prompt is admitted" are different claims. Only the first was
  established, and the second was reported.
- **Acceptance ran against a clean home.** A fresh install cannot exhibit a
  defect that only exists when a home's committed state has drifted from the
  installed runtime. A clean-home pass was read as evidence of a fix when it was
  evidence of nothing.
- **The masked error code was believed.** `native_request_invalid_json` sent the
  investigation at serialization and payload size, and a correct early
  hypothesis was dropped as disproven on the strength of that code. The
  rewriting in `safe_error_response` was found only after reading the emission
  site in the Rust source instead of trusting the wire.
- **"Released" was reported as "fixed."** A merged PR and a published version
  are facts about the repository. Neither is a fact about the machine that
  reported the problem.
- **The test fixture did not model the thing that refuses.** The second attempt
  was declared fixed on a suite that passed. Its fake resident accepted any
  push that carried no command binding, so it modelled a resident with no
  command-control floor — which no affected home is. The suite proved the
  publisher does what it was written to do, not that the resident would accept
  it. A reviewer found the floor; the tests could not have. A fixture that
  stands in for the component under test has to be checked against that
  component's real refusals before its passes mean anything.

## What changed so this does not repeat

The acceptance rules are now written down, in
`guard-gauntlet/references/installed-acceptance.md`, and referenced from the PR
review loop and the dev-testing skill. The claim that has to be met before a
runtime fix is called shipped:

> On the machine and configuration that reported the problem, a prompt that was
> failing now completes, and a prompt that should be stopped is still stopped.

With the supporting rules that this incident cost: reproduce through the
production wiring that emitted the message, run acceptance against the reporting
configuration rather than a clean one, never root-cause from a wire code without
reading its emission site, prove the new test fails without the fix, and state
which claim you actually hold.

One rule was added after the second attempt: a fixture that stands in for the
component the fix depends on has to be checked against that component's real
refusals. A fake that accepts what the real one rejects turns a green suite into
evidence of nothing.
