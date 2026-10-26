# Policy command reference

All commands are under `hol-guard policy`. Commands that read a policy file never need a Guard home, so
they work in CI and on a laptop where Guard has never run.

Common flags: `--format text|json` (or `--json`) chooses the output shape. `--home <dir>` and
`--guard-home <dir>` pick the Guard home for commands that read it.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success. For `test`, every case passed. |
| 1 | `test` had a failing or ambiguous case, or `diff` / `fmt --check` found a difference. |
| 4 | The input was invalid or the command could not run. JSON output carries an `error` code. |

## init

```bash
hol-guard policy init [--starter <name>] [--output <file>] [--force] [--list]
```

Writes `guard-policy.yaml` (or `--output`) from a [starter](STARTERS.md), with the editor modeline and two
example tests. An existing file is never overwritten without `--force` (`policy_file_exists`). An unknown
starter name is `unknown_starter`.

## validate

```bash
hol-guard policy validate <file> [--format json]
```

Checks the file against the [schema](schema-reference.md) and the rules Guard can enforce. Text output
shows the first 20 problems. `--format json` is uncapped.

Each diagnostic has this shape:

```json
{
  "code": "forbidden_sensitive_field",
  "path": "spec.rules[0].match.secretValue",
  "line": 15,
  "col": 22,
  "message": "A field name looks like it holds a secret. Policies must not store credentials.",
  "expected": "optional, what was expected",
  "suggestion": "optional, what to do about it"
}
```

`status` is one of `valid`, `schema_invalid` or `not_enforceable`. `schema_invalid` means the file is not a
valid policy. `not_enforceable` means it is a valid policy that this version of Guard cannot compile into
device rules, for example a match field that only Guard Cloud evaluates. A policy file that other users can
write to is reported with `suggestion: "chmod 600 <file>"`.

## test

```bash
hol-guard policy test <file> [--watch] [--format json]
```

Runs every example under `spec["x-hol.tests"]` and prints `PASS`, `FAIL` or `AMBIGUOUS` for each. A failing
case exits 1. `--watch` reruns when the file changes. A test list that is malformed, repeats an id or
names an unknown rule is `x_hol_tests_invalid` and exits 4.

## check

```bash
hol-guard policy check <file> --event <json|-> | --command "<command>" [--format json]
```

Decides one event against the file and prints the Decision: the effect (`allow`, `block` or `default`), the
winning rule, every candidate with its state and reason, and whether the result was
ambiguous. `--event -` reads the event from standard input (up to 64 KiB). `--command` checks a shell
command against command rules; for those, `action` carries the strongest action asked for, including `warn` and
`review`, which have no `allow` or `block` effect. Command rules need the Guard 3.1 runtime, so `--event` and
`policy test` decide with the file's other rules. A file with business rules cannot be checked or tested
locally: `check` exits 4 and `test` fails each example with `business_rules_not_evaluated_locally`. The JSON shape is
[`decision.schema.json`](../../spec/guard-policy/v1alpha1/decision.schema.json). See
[precedence](precedence.md) for how the winner is chosen.

## status

```bash
hol-guard policy status [--offline] [--format json]
```

Shows the policy installed on this device, then the Cloud bundle's version, mode, last sync, last
acknowledgement and any rejection reason. Unless
`--offline`, it also reads Guard Cloud's delivery state. If you are signed out, offline or Cloud does not
offer the route, `delivery.available` is `false` with a `reason` and the command still succeeds.

## explain

```bash
hol-guard policy explain [<decisionId>] [--format json]
```

With a decision id (a receipt id), replays that receipt's event against the policy that is Live now and
names the rule that would decide it today. Unknown ids are `decision_not_found`. Without an id it
explains the Live policy as a whole. Receipts do not record the publisher or workspace, so when the Live policy has
rules scoped to either, the result carries the note `publisher_and_workspace_scopes_not_replayed`.
`hol-guard history explain` also includes a `matched_rule` field.

## diff

```bash
hol-guard policy diff <file> [--format json]
```

Compares the file with the policy that is Live on this device. Exits 1 when they differ.

## export, fmt and import

```bash
hol-guard policy export [--output <file>] [--include-provenance]
hol-guard policy fmt <file> [--check]
hol-guard policy import <file> (--merge | --replace) [--dry-run | --apply] [--yes]
```

`export` writes the Live policy with the editor modeline, to standard output unless `--output` is given. `fmt` rewrites a file in canonical form and
`--check` exits 1 if it is not already canonical (a missing modeline alone does not count). `import` is a dry run unless you pass `--apply`: it prints the diff against Live and stops. With
`--apply` it asks you to confirm the diff, or you can pass `--yes`. With `--format json` there is no prompt: run a dry run to see the diff, then pass `--yes`. Applying still goes
through Guard's approval gate; `--yes` only skips the diff confirmation. No environment variable is needed.

## Related commands

The policy that a device applied is also part of the [fleet posture](../guard/fleet-posture.md) that Guard
reports to Guard Cloud. `hol-guard cloud status` shows the last posture sent and what Cloud currently shows
for this machine, and `hol-guard settings set fleet-posture off` limits that report to version, protection
state and policy status (not available on managed installs).
