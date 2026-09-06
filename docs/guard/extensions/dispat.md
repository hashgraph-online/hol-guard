# Dispat release protection

`command.dispat` is an external, opt-in Guard command Extension. Once enabled locally, its
`command.dispat.release` rule reviews release starts with high severity and the `execution` and
`network_egress` risk classes. Guard policy retains the final decision.

For help, JSON logs, CI gating, CCME commits, configuration boundaries, release-lock coordination,
gating versus warning-only hooks, and idempotent publishing, see
[Using Dispat as an agent](dispat-agent-guide.md).

> **Agent workflow: release only through CI/CD.** Agents must not execute bare `dispat`,
> `dispat release`, or equivalent publishing work themselves. Prepare and validate changes, then
> leave release execution and retries to the repository's reviewed CI/CD release workflow. Do not
> bypass it with script helpers, manual publishing, or release-tag/record changes. A Guard approval
> does not replace this workflow requirement.

This guidance does not change the runtime rule below: the Extension reviews release starts and does
not enforce CI-only execution or detect every alternative publishing command.

> **Important:** With release locking enabled, both `dispat` and `dispat release` first attempt to
> acquire the remote `dispat-release-lock` tag before planning or executing release work. This also
> applies to `--require-release`: even a run that ultimately has nothing to publish takes the lock
> and then releases it. Use `dispat status --require-release` as the documented CI gate without a
> release lock; use `dispat status` to preview the plan. Release invocations therefore require
> review before lock acquisition, not only before publishing.

Locking is disabled only by an explicit unsafe override. In the source version referenced below, the
configuration key is `unsafeDisableLock: true`; `DISPAT_UNSAFE_DISABLE_LOCK=true` also disables it
for an invocation. This Extension does not inspect either override or exempt a release when locking
is disabled.

| Invocation                                       | Dispat rule behavior when enabled                         |
| :----------------------------------------------- | :-------------------------------------------------------- |
| `dispat`                                         | Review the default release start.                         |
| `dispat release`                                 | Review the explicit release start.                        |
| `dispat --package api`                           | Review the selected package's release start.              |
| `dispat --root ./repo release --group libraries` | Review with reordered selection/global options.           |
| `dispat status --package api`                    | No release evidence; show the release plan.               |
| `dispat release --help` or `dispat --version`    | No release evidence; these exit before release execution. |
| `dispat --help=false`                            | Review; disabling help still starts the default release.  |

The preview counterpart is `dispat status` with the same root, configuration and selection flags.
Dispat has no release `--dry-run` option. Unknown options, missing option values and malformed
release arguments retain uncertainty evidence for review; they do not establish a safe preview.

The matcher uses Guard's canonical command segments and shared option handling. It supports
executable paths, the `dispat.exe`/`dispat.cmd` spellings, short selection options and wrappers
understood by Guard. Option values are never treated as command words: `dispat --package status`
starts a release, while `dispat status` previews it. Help and version boolean assignments use
Dispat's last-assignment-wins behavior.

Other Dispat subcommands and script shorthands are outside this rule. This is not an allow decision
for those commands or the surrounding shell: `dispat status; rm -rf /` still retains the filesystem
rule's evidence. No Dispat configuration or scripts are read or executed by this Extension, and no
MCP integration is involved.

The command contract was checked against Dispat commit
[`909dc401f3725a610604b77b0e790808cee9a524`](https://github.com/yohimik/dispat/tree/909dc401f3725a610604b77b0e790808cee9a524),
specifically `services/dispat/internal/cli/{cli,options,dispatch,usage}.go` and
`services/dispat/internal/app/{release,lock}.go`. See the
[Dispat repository](https://github.com/yohimik/dispat) and
[release-lock documentation](https://github.com/yohimik/dispat/blob/909dc401f3725a610604b77b0e790808cee9a524/packages/docs/docs/reference/releasing/release-lock.md)
for the release pipeline and lock-free gate.
