# GiviLoop CLI extension

`command.givi` reviews six direct `givi` CLI operations when a local
administrator enables this **external** extension. GiviLoop does not need HOL
Guard or any code changes. The extension does not add another GiviLoop review,
certify findings, or promise token savings or a human prompt on every call.
Existing Guard policy and authenticated controls determine the final action.

## Upstream behavior and scope

This boundary was checked against the GiviLoop **0.9.0 release candidate**, at commit
[`bb97231e82585599417320d901e63591b358a720`](https://github.com/vgflutter/GiviLoop/tree/bb97231e82585599417320d901e63591b358a720).
The relevant dispatch and argument parser are
[`main`](https://github.com/vgflutter/GiviLoop/blob/bb97231e82585599417320d901e63591b358a720/src/cli.ts)
and [`autoReviewCommand`, `findingsCommand`, `parse`, `reportCommand`](https://github.com/vgflutter/GiviLoop/blob/bb97231e82585599417320d901e63591b358a720/src/workflow-commands.ts).

| Direct CLI operation | Effect and reason for review | Permission suffix |
| --- | --- | --- |
| `givi auto-review enable` | Writes automatic-review policy, managed agent instructions and supporting configuration; `--client codex` also changes managed client settings/tool approvals. | `auto-review-config` |
| `givi auto-review disable` | Revokes the policy and removes managed instructions/client configuration. Does not cancel an in-flight review. | `auto-review-config` |
| `givi auto-review acknowledge` | Writes acknowledgement to history and can permit new tasks after an unresolved attempt. Does not resend or certify the old review. | `auto-review-config` |
| `givi auto-review run` | May skip, or save a new run/history and send selected code to the configured local or web reviewer. | `auto-review-run` |
| `givi findings add` | Creates a finding and its first assessment, including confirmed/dismissed decisions when application requirements are satisfied. | `findings-write` |
| `givi findings update` | Appends an assessment to the selected run/finding, preserving the original title and claim. | `findings-write` |

Permission IDs start with `command.givi.permission.`. Rules are named
`command.givi.auto-review-enable`, `auto-review-disable`,
`auto-review-acknowledge`, `auto-review-run`, `findings-add` and `findings-update`
(all with the same `command.givi.` prefix).

`acknowledge` and `findings add` are included because they change automation
state and recorded assessments respectively. The grouping separates automation
configuration, possible submission, and evidence writes. All three permissions
have a `review` baseline and medium risk; all six rules use `review` mode and
medium severity. The `execution` risk class describes agent action review:
these operations are not all destructive, and a local reviewer is not remote
network egress. No rule claims to inspect or approve the transmitted payload.

The implementation uses `leading-subcommand.v1`, `executable.v1` and `any.v1`.
It contains no executable-wide or `unclassified` rule, Python detector, custom
callback, or runtime change. The source's `built-in` inventory marker does not
grant trust: the separately reviewed trust map classifies it as `external`.

## What is not covered

`auto-review status`, `findings list` and `report` receive no additional
requirements from this extension. This is not a global allow rule. In
particular, `report` and `report --json` can write `double-check.md`;
`report --stdout` avoids saving the report but still acquires a disk lock.
See [`exportReviewReport`](https://github.com/vgflutter/GiviLoop/blob/bb97231e82585599417320d901e63591b358a720/src/review-report.ts)
and [`acquireRunLock`](https://github.com/vgflutter/GiviLoop/blob/bb97231e82585599417320d901e63591b358a720/src/run-lock.ts).

Other submissions (`opinion`, `review`, `send`, `resume`, `ask --send`, `archive --send`),
preparation, import/clipboard, onboarding, demonstrations and browser management
are outside this first contribution. Some of them write files or send code.
This extension is not complete protection for GiviLoop or code transmission.

The normal automatic workflow uses direct MCP calls. Those calls and server
launches (`givi-mcp`, `npm run mcp`, Node on `mcp-server.js`) are outside this
CLI extension. [`mcp-server.ts`](https://github.com/vgflutter/GiviLoop/blob/bb97231e82585599417320d901e63591b358a720/src/mcp-server.ts)
calls the application functions directly; a shell rule does not prove MCP
coverage. Coverage also depends on the agent exposing the shell event to Guard;
this contribution does not install hooks or monitor arbitrary child processes.

## Invocation and parsing boundaries

The covered executable basename is `givi`, including quoted paths containing
spaces. This is syntactic recognition, not binary authentication. Windows
`givi.cmd`/`givi.exe` entry points and Windows shell behavior are not claimed.

`npm run givi -- ...` is a documented GiviLoop invocation, but `givi` is only an
npm script name there. Node paths such as `dist/cli.js` are also ambiguous.
Neither is attributed to this extension, even if another Guard policy already
reviews or blocks the command. `setup()` can print absolute Node/CLI paths;
those remain excluded too. No package/script is imported or executed to infer
identity. See the upstream
[`package.json`](https://github.com/vgflutter/GiviLoop/blob/bb97231e82585599417320d901e63591b358a720/package.json)
and [`setup()`](https://github.com/vgflutter/GiviLoop/blob/bb97231e82585599417320d901e63591b358a720/src/setup.ts).

Native tests demonstrate `sudo -n givi ...` with exact GiviLoop rule evidence.
Its independent `require-reapproval` floor remains. `env`, shell `-c`/`-lc`,
`exec`, `command` and `xargs` wrappers tested here remain uncertain and blocked;
they are not supported merely because Guard stops them.

Known value options may appear before or after the action, including
`--name=value`, repeated `--file`/`--evidence`, and values equal to action names.
`--json` can precede a findings action. Ordinary `--help`/`-h` narrows only its
own rule's segments. Help in one command cannot suppress a subsequent write.

The pinned candidate dispatches the command before its operation-specific parser.
Use the canonical `givi auto-review ACTION ...` or `givi findings ACTION ...`
forms with `--repo` and `--file`. It does not include `src/cli-interface.ts`:
`--repositoryPath`, `-f`, bare findings/auto-review defaults and the `opinion`,
`answer`, `login`, `check` shortcuts from the earlier development checkout are
not supported. The extension retains conservative recognition fixtures for
those older aliases; this is not a claim they execute on the pinned candidate.

Help narrows a rule only when the native matcher proves it is a flag, not an
option value. A value such as `--reason=-h` must not erase a write. The candidate checks separated `--help`/`-h` anywhere before dispatch, including
when supplied as an option value. Guard may conservatively review those no-op
forms. It does not treat `--` as a blanket help escape. Compact short options
before the action (for example `findings -ffile add`) and delimiter-separated
actions are not claimed as supported; use the canonical `givi findings add ...`
form or separated named options. `--version` is only a root command and there
is no generic `--dry-run`. Invalid attempts are not certified safe; some retain
the operation rule and others fall back to Guard's existing handling.

The matcher policy intentionally treats unknown options conservatively: they
must not turn a recognized write into an unreviewed action. Help safe variants
are stricter because suppressing a review requires proving that the invocation
is only help. Flags listed in both value-option and forbidden-flag sets are
consumed with their values; a bare occurrence cannot stand in for an action.
The second findings matcher explicitly recognizes the historical token sequence
`findings --json add|update`; the native schema calls that sequence `subcommands`,
which does not make `--json` a GiviLoop subcommand. These compatibility cases do
not claim the current CLI accepts every historical form.

## Review identity and controls

[`recordFinding`](https://github.com/vgflutter/GiviLoop/blob/bb97231e82585599417320d901e63591b358a720/src/review-evidence.ts)
requires an explicit `runId` and looks up an update's finding only in that run.
CLI updates use `--id`; MCP uses `id`; results expose `findingId`. Guard neither
adds missing IDs nor selects latest nor rewrites arguments. GiviLoop still
validates evidence and review identity; the coding agent independently verifies
the claims. Some reads retain an optional latest-run convenience.

An external extension is inert until local-admin enable and becomes inert
again when disabled. Disabling a permission while the extension is active can
block the corresponding operation. Signed-cloud enable alone cannot activate
it. Help and exclusions never override independent policy requirements or
managed controls.

## Authoring and validation

Use the supported [direct-source preparation and handoff](extensions/contributing.md)
path. The generic Builder inventory generator adds an `unclassified` rule, so
its default output is not this six-operation boundary. Generated descriptors,
programs, catalogs and directory pages must only be regenerated by repository
tooling.

The portable fixture binds the exact source and a self-contained native
baseline, without `base: "packaged"`; rebuilding an integrated compiler must
not turn it into a duplicate addition. Run the same cases with the
[complete checkout envelope](extension-builder/VALIDATION.md#validate-an-integrated-command-fixture)
as well. Both runs must report `target_commands_executed: 0`.

`tests/test_guard_command_givi_extensions.py` checks native inspection/runtime
evidence, all-rule exclusions, local versus managed activation, disabled
permissions, Unicode operands, exact sudo attribution, uncertainty, and
independent floors. It does not launch GiviLoop or a reviewer. The sudo result
is tested there because the portable fixture's action enum does not include
`require-reapproval`.

Follow the native build/regeneration order and focused gates in the contribution
guide, then run:

```sh
uv run --no-sync hol-guard extensions handoff --repo . \
  --source contributions/command-sources/command.givi.json \
  --fixture tests/fixtures/command-source-givi.v1.json
```

Local source tests and handoff do not establish release availability, installed
wheel qualification, maintainer acceptance, or activation on a device.

The GiviLoop candidate's `test/hol-cli-contract.test.mjs` separately executes all
six canonical operations against a synthetic local reviewer. It creates two
reviews, rejects missing/wrong review IDs and checks that finding writes and
acknowledgement do not resubmit. This complements the native fixtures; neither
proves protection of direct MCP calls or acceptance by a web provider.
