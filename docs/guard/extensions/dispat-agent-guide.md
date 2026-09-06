# Using Dispat as an agent

This guide complements [Guard's Dispat release protection](dispat.md). It describes how to inspect a
Dispat repository and prepare a release without expanding Guard's release-start rule. Commands shown
here are examples to adapt to the user's task, not permission to run a release.

## Inspect the tool and configuration first

Use help explicitly: a bare `dispat` starts a release.

```sh
dispat --version
dispat --help
dispat status --help
dispat release --help
```

Command-specific help describes the installed binary's supported flags. There is no release
`--dry-run` flag. `dispat <script>` can execute a configured script when the word is not a built-in
command; an unfamiliar word is not a discovery command. See the [CLI reference][cli].

> **Important: configuration changes require a direct user instruction.** Read the existing Dispat
> configuration to understand the task. Do not create, rewrite, or "repair" it, run `dispat init`,
> apply `dispat compute --write`, or change release hooks, publishing commands, channels,
> credentials, or lock settings unless the user directly asks for that configuration change. A
> request to inspect or release a project is not by itself an instruction to change its release
> policy. If configuration is missing or prevents the requested work, report the specific issue and
> ask for direction.

Start with the [configuration reference][configuration]. Discovery checks `dispat.json`,
`dispat.yaml`, `dispat.yml`, then `dispat.toml`, and can ascend to a parent repository
configuration. `--root` sets the starting location; an explicit `--config` selects that file without
fallback. Package and space configuration, inheritance, and `$ref` files can also affect the
effective settings. Inspect the relevant declarations, not just the first root file.

| Configuration topic                                                                                      | Why an agent needs it                                                                |
| :------------------------------------------------------------------------------------------------------- | :----------------------------------------------------------------------------------- |
| [Packages], [spaces], and [dependencies]                                                                 | Identify package names, paths, groups, and provider ordering.                        |
| [Scripts] and [run hooks][hooks]                                                                         | Determine what version, build, publish, login, and run-level work can execute.       |
| [Release records][records] and [tags/baselines][versions]                                                | Understand release commits, remote pushes, tag formats, and GitHub/changelog output. |
| [Parser settings][parser] and [change ownership][change-scope]                                           | Understand how commits select packages and affect versions.                          |
| [Environment files][dotenv], [configured environment][environment], and [configuration references][refs] | Trace effective inputs without printing credentials or copying them into logs.       |

The default `.env` is read from the invocation directory, not from `--root`. `--env-file` replaces
that default and may be repeated. Keep the working directory and relevant flags consistent between
inspection and release. Do not dump `.env` contents or secret values into an agent response.

## Preview the same selection you intend to release

```sh
dispat status --log-format json
dispat status --package api --strict --log-format json
dispat preview --package api --changelog --github
```

`status` computes the plan without running release stages or taking the release lock. `preview`
renders pending release notes; it cannot predict exports that only become available during
publishing. See [status] and [preview].

Use the same `--root`, `--config`, environment, and selection for the eventual release. An explicit
`--package` (`-p`), `--space` (`-s`), or `--group` (`-g`) overrides implicit selection from the
current folder. Quote globs such as `-p '@acme/*'`. `-p '*'` includes standalone packages that
`-s '*'` may miss. Selection narrows which packages release; the full graph still determines their
versions.

Review `W230` for consumers withheld because their providers were not selected, and `W231` for a
split versioning group. Use the intended whole group or add the required providers with user-agreed
scope; do not bypass those findings by editing configuration. `--strict` makes these selection
problems fail. An exit code of `0` from ordinary `status` can still accompany warnings about a plan
that a release would refuse, so read the diagnostics too. See [partial releases][partial].

## Use JSON logs and preserve exit codes

`--log-format json` makes Dispat's logger emit JSON lines. Consume individual records and diagnostic
`code` fields rather than scraping colored console text. Use `--log-level debug` to explain config
resolution and planning; reserve `trace` for detailed diagnostics and review its contents before
sharing. `--quiet-parser=false` restores parser diagnostics when configuration suppresses them.

**CI/CD logs can provide release visibility without webhooks.** For an already-authorized release,
use `dispat release --log-format json` in the release job. People can follow the CI platform's live
job logs, and agents with access to those logs can consume the same JSON records to track progress
and diagnose failures. Retain logs as CI artifacts when later inspection is useful. This needs no
webhook endpoint or webhook configuration; availability and streaming depend on the CI platform. The
command still starts a release and remains subject to Guard review. Read the final command exit
status and diagnostics as well as progress records.

The flag controls logging, not every command's entire output: help/version text and rendered preview
notes have their own formats. Do not assume arbitrary configured scripts emit JSON. Preserve stderr
and the command's exit status; piping output through a parser must not turn a failed Dispat command
into a successful pipeline. See [diagnostic codes][diagnostics].

For a lock-free CI gate, capture the exit status before deciding what to do:

```sh
rc=0
dispat status --require-release --log-format json \
  > dispat-status.jsonl 2> dispat-status.stderr || rc=$?
case "$rc" in
  0) printf '%s\n' 'Review the plan; release work is pending.' ;;
  3) printf '%s\n' 'Nothing to release.' ;;
  *) cat dispat-status.stderr >&2; exit "$rc" ;;
esac
```

| Exit code for `status` / `release` | Meaning                                                                          |
| :--------------------------------- | :------------------------------------------------------------------------------- |
| `0`                                | Successful command; without `--require-release`, this can include an empty plan. |
| `1`                                | Failure or refusal; on release, some packages may already have published.        |
| `2`                                | Invalid CLI usage, including a flag belonging to another command.                |
| `3`                                | `--require-release` found nothing to release.                                    |

Do not use a catch-all `|| true` or treat every nonzero exit as "nothing changed." The gate does not
start a release or grant Guard approval. These exit-code meanings are command-specific; script
helpers can return their scripts' own codes.

## Gate on the full suite before starting a release

The status gate answers whether release work is pending. A separate full-suite gate checks whether
the proposed change breaks other modules, including modules that did not change. Use Dispat's own
[release workflow][release-ci] as the reference: its `Full suite` job runs before the release job,
and the release job declares `needs: [tests, ping]`. A failed suite or failed cleanup prevents that
job from starting; the checks are not deferred to warning-only release hooks.

The workflow temporarily links workspace dependencies to the checkout so consumers exercise the new
provider code rather than an older published version. It then runs every package's configured
`tests` script and always removes and verifies the links:

```yaml
# Excerpt from Dispat's release workflow; these script and package names are repository-specific.
- name: Link the workspace dependencies
  run: dispat run link --since all -p dispat

- name: Run every package's tests
  run: dispat run tests --since all

- name: Unlink the workspace dependencies
  if: always()
  run: |
    dispat run unlink --since all -p dispat
    # Dispat-specific verification; optional when adapting this pattern to another project.
    dispat run verify-unlinked --since all -p dispat
```

These steps run from the repository root. In another repository, inspect existing scripts and
selection first; `link`, `unlink`, `verify-unlinked`, and `tests` are configured script names, not
built-in commands. `--since all` widens the window to every package, but folder or explicit
selection still narrows it. Use `--package '*'` when an explicit all-package selection is needed,
including standalone packages. A package without the named script can do nothing: verify that every
relevant module has test coverage, and run repository-wide integration checks with the repository's
own tools when they are not represented by a package script. See [run].

The [Dispat package configuration][dispat-package-config] defines `link` as
`dispat autowriter --package dispat --since all --sync-lock=false --link-local`, and `unlink` as the
same command with `--unlink-local`. This rewrites local dependency redirects; it does not publish
new dependency versions. The verification script checks for surviving redirects with
`dispat scanner --root-only --verify-unlinked` and checks the required Go checksum entries with a
repository script. See [autowriter] for the supported manifest formats and flags.

A separate `verify-unlinked` script is optional when adopting this pattern; choose verification
appropriate to the project's ecosystem and existing checks. Dispat's own CI requires its script to
protect consumers from leftover local redirects and missing Go checksums. It can catch writer
regressions, but also incomplete cleanup or checksum changes made by other toolchain commands. This
is not a requirement to add the same script to every project or permission to remove an existing
required check. Removing temporary links before publishing remains necessary even when there is no
separate verification script.

Use a disposable CI checkout for temporary manifest edits and preserve cleanup even when tests fail.
A release does not automatically remove local links. For Go, avoid `go work sync` or `go mod tidy`
while links exist: they can drop checksum entries needed after unlinking. Derived `--link-local`
edits skip `package.json`; use the repository's existing ecosystem workspace/linking tools where
appropriate. Do not invent replacement scripts or change Dispat configuration without the direct
user instruction required above.

Dispat orchestrates the dependency order; the ecosystem tools perform the checks. In its own
repository, the [package scripts][dispat-pkg-config] call Docker Buildx targets in
[`Dockerfile.gotest`][dispat-test-dockerfile], which run Go tests and vet with the repository's test
reporting tools. Adapt the pattern to the target repository's existing build, lint, type-check,
unit, and integration suites. Preserve failures through every wrapper and require the gate to pass
for the revision being released. Do not treat `--on-error continue` as success: it lets dependent
work proceed, but `dispat run` still exits `1` if any script fails.

For faster PR feedback, Dispat's [test workflow][test-ci] instead uses
`dispat run tests --since "$(sh scripts/ci-base.sh)" --consumers`, with a repository-specific base
selection helper. This includes transitive consumers of changed packages but is not the all-package
pre-release suite. Successful full-suite results provide evidence against cross-module regressions
within the tests' coverage; they cannot guarantee that every possible regression is absent.

Keep checks for the published form as well. Dispat's [package][dispat-pkg-config] and
[service][dispat-services-config] configurations run `tests:release` in the gating
`flow.beforeBuild` hook, after version reconciliation and lockfile synchronization. These tests
resolve published provider tags without workspace redirects, checking what consumers will fetch.
They complement the full checkout suite; they run inside the release, where earlier providers may
already have published. `dispat run <script>` executes the named script, not the surrounding release
hooks, so it does not implicitly run these additional gates.

## Let pnpm manage its workspace dependencies

For a monorepo already using pnpm workspaces, prefer its existing workspace mechanism: keep internal
dependency ranges such as `"@acme/core": "workspace:*"` in the repository throughout development and
release. pnpm resolves them locally and substitutes publishable versions when packing or publishing.
These persistent declarations are not temporary redirects to unlink. See the
[pnpm workspace documentation][pnpm-workspaces] and [Dispat's pnpm example][dispat-pnpm].

Dispat's derived `autowriter --link-local` edits skip `package.json`; they do not set up pnpm's
workspace protocol. A pnpm repository that already declares `workspace:*` needs no Dispat
link/unlink cycle or dependency-range rewrite for local testing. Run its existing pnpm build and
test scripts, directly or through `dispat run`, with the full-suite coverage described above.

If the user explicitly requests a dependency-range edit, [writer] can set the literal:

```sh
dispat writer packages/web/package.json --set '@acme/core=workspace:*'
```

Use `--set` for a dependency declaration; `--set-version` changes the containing package's own
version and must not receive `workspace:*`. This command edits a manifest; it is not a prerequisite
for using pnpm or permission to change the repository's dependency policy.

Keep dependency linking separate from release versioning. pnpm handles workspace resolution and
packing, while the repository still needs its chosen mechanism to assign package versions. Do not
add Dispat auto-versioning merely to link local dependencies. If the repository already uses it,
Dispat's pnpm example preserves the protocol with `autoVersion.range: "workspace:*"` while updating
package versions, synchronizing `pnpm-lock.yaml`, and including that root lockfile in the release
commit. Inspect the existing policy; do not disable it or change configuration without a direct
instruction. Check packed artifacts according to that policy instead of applying a blanket
`--forbid-range 'workspace:*'` gate to source manifests that intentionally retain the protocol.

## Use configurable webhooks for release observations

Webhooks are optional. Use [JSON job logs](#use-json-logs-and-preserve-exit-codes) when people and
agents watch through CI/CD; configure webhooks when an external receiver needs pushed events.

Dispat supports [webhooks] for release, stage, and package events, plus script events raised with
[`dispat trigger`][trigger]. Agents can read these events to follow progress without scraping
console output. The default body is JSON; `format` supplies a custom payload template for a
receiver's expected shape. For example, an existing configuration might contain:

```yaml
webhooks:
  - url: https://ci.example.com/dispat-events
    events: [package.published, package.failed]
    format: '{"text": "{package} {version}: {event} {error}"}'
```

Supported scalar placeholders are substituted with escaping for JSON string positions. Use the
documented field names; unknown placeholders fail configuration loading. Options also control event
subscriptions, HTTP method, headers, timeout, environment conditions, and signing through
`secretEnv`. Package and space webhook lists replace inherited lists rather than append to them.
Read the existing configuration; adding or changing endpoints, payloads, or credentials requires the
same direct instruction as other configuration edits.

Webhooks are asynchronous observers and never gate a release. Delivery failures warn with `W239`
without changing the release exit status; put required checks in a gating script or CI job.
Receivers should account for retries using `X-Dispat-Delivery`. Release events start only once the
run proceeds to execution, so an early refusal may emit none. A successful notification is not proof
that every release operation succeeded; inspect the relevant event and command outcome.

## Respect an active release lock

> **Important: defer unrelated pushes while the release lock exists.** Avoid pushing to the branch
> being released, changing its release tags, or starting another release until the current run has
> finished. The lock coordinates Dispat releases; it does not prevent ordinary `git push`
> operations. This is agent workflow guidance, not a new Git-blocking rule in the Guard Extension.

Check the actual release remote rather than relying on a local tag. For a repository using `origin`:

```sh
git ls-remote --refs origin refs/tags/dispat-release-lock
```

Use the repository's configured release remote if it differs. A returned ref means a release may be
active or a lock was left behind. A failed lookup does not mean the lock is absent, and an empty
result is only a point-in-time observation; Dispat's own acquisition still resolves races. Do not
delete, force-update, or disable a lock to make progress. If it appears abandoned, have the operator
confirm the owning run is gone and explicitly authorize cleanup. See [release locking][lock].

Dispat handles some concurrent pushes by merging arriving commits. `W242` reports recovery; `W243`
reports conflicts preserved on a `release-conflicts/...` branch for reconciliation. Those outcomes
need review even when the release exits `0`. Avoid creating this situation with an unrelated push.
If the remote already contains a version tag the run would overwrite, recovery refuses with `E224`.
See [release recovery][recovery].

## Write commits with the repository's CCME intent

Dispat uses Conventional Commits: Monorepo Extension (CCME). Read the
[normative CCME 2.0.0 specification][ccme], [commit reference][commits], and the repository's
[parser settings][parser] before inventing commit syntax or predicting a version. Configuration can
change the defaults.

| Commit-message example                       | Default release intent                           |
| :------------------------------------------- | :----------------------------------------------- |
| `fix(api): handle an empty response`         | Patch the named package.                         |
| `feat(api,web): add pagination`              | Minor bumps for both named packages.             |
| `feat(api)!: remove the legacy endpoint`     | A breaking change requests a major bump.         |
| `feat(api)^: add a consumer-facing field`    | Release `api` and propagate to direct consumers. |
| `feat(api)^^: update the shared protocol`    | Reach transitive consumers.                      |
| `feat(api)%beta: introduce the new endpoint` | Move the directly addressed package onto beta.   |

Scopes refer to configured packages; omitted scopes derive ownership from changed files. Several
units separated by a line containing `---` can express independent changes in one commit. Both bump
propagation and channel propagation default to depth zero and are independent: `^`/`^^` do not by
themselves move consumers onto beta. Read the specification before using channel propagation,
`Release-As`, `cancel`, `Edits`, or `Deletes`; these alter pending release intent and are not
ordinary descriptive prose. Do not add them unless they express the user's requested release
behavior.

Git release tags record the version history. A changed manifest version alone is not a complete
prediction of what Dispat will release. Use `status` to inspect the computed result. For tools that
need to parse CCME messages, the [Go parser API][ccme-api] explains structured units and
diagnostics; the Guard command Extension does not parse commit messages or implement CCME itself.

## Know which stages gate a release

Read [Stages and hooks][stages] and [run-level hooks][hooks] before changing or relying on a
pipeline. Package `flow` hooks and top-level `run` hooks have different scopes and failure rules.

| Stage or hook                                                                                                                          | Failure behavior                                                                                                                                                                             |
| :------------------------------------------------------------------------------------------------------------------------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `run.beforeAll`                                                                                                                        | The only gating run-level hook; failure stops the run before the task graph starts. The release lock has already been acquired.                                                              |
| `flow.beforeAll`, `flow.beforeVersion`, native auto-version reconciliation, `flow.version`, `flow.postVersion`, `autoVersion.syncLock` | Gating package work before build; failure prevents that package from proceeding. Version work runs only where applicable.                                                                    |
| `flow.beforeBuild`, `flow.build`, `flow.postBuild`                                                                                     | Gating package work; failure prevents publishing.                                                                                                                                            |
| `flow.login`                                                                                                                           | Gating authentication, once per space; failure prevents that space's publishes.                                                                                                              |
| `flow.beforePublish`, `flow.publish`                                                                                                   | The last gating hook and gating stage respectively. A nonzero publish exit fails the package; Dispat does not record it as published.                                                        |
| `flow.postPublish`, `flow.beforeAnnounce`, `flow.announce`, `flow.postAnnounce`                                                        | Warn-only after successful publish. Failure does not undo publishing or stop the later observer sequences.                                                                                   |
| `flow.onFail`, `flow.onSkip`                                                                                                           | Warn-only observers of a failed or skipped package, not recovery gates.                                                                                                                      |
| `run.postAll`, `run.beforeCommit`, `run.afterCommit`, `run.postCommit`, `run.beforePush`, `run.afterPush`                              | Warn-only run observers. In particular, `run.beforePush` cannot veto a push. Commit/push hooks apply only when those operations are performed; after-hooks require the operation to succeed. |

Gating package failures can skip consumers while independent packages continue. A hook named
`before...` is not necessarily a gate: the post-publish `beforeAnnounce`, `beforeCommit`, and
`beforePush` hooks are observers. Put required checks in the gating half, not in a warning-only
notification or announcement hook. On interruption, Dispat can skip post-publish observer scripts
while finishing durable release records; do not rely on those observers to make publication
complete.

> **Important: publish scripts must be idempotent for retries.** For the same package, version, and
> artifact, retrying publication must not duplicate or overwrite a different release. Return success
> only when the intended publish has completed, or when the exact existing artifact has been
> verified as the same completed publish. Keep required release work inside the gating stages:
> `publish` is still gating, but after it succeeds the script hooks only warn. This separation,
> along with durable release records and a retry-safe publish implementation, is what makes safe
> retry and convergence possible. Dispat cannot make an arbitrary shell command idempotent for you.

Do not blanket-ignore publish errors or treat every "version already exists" response as success. A
script can publish remotely and then exit nonzero, or lose its response; verify the destination
before a retry. Only change a publish script when the user directly authorizes that change.

**Native recording failures are not warning-only script failures.** After publish succeeds, failures
to write tags, changelog/GitHub records, release commits, or pushes are critical errors
(`E220`–`E224`). The package remains `published`, remaining recording work continues, and the
command exits `1`. That protects the distinction between "not published" and "published but
incompletely recorded." See [After the point of no return][post-publish] and
[standalone release steps][steps].

## Recover and choose other commands deliberately

After a failed or interrupted release, inspect the plan, per-package results, and existing release
records. Dispat can resume work not yet recorded, but a publish may have succeeded just before the
process stopped and before its tag was written. Verify that package's registry or destination before
retrying; do not assume a nonzero exit means nothing published or blindly retry forever. A retry is
another release start and remains subject to Guard review. See [recovery].

Other useful inspection commands include `dispat scanner <folder> --log-format json` for manifest
declarations and plain `dispat compute` for suggested graph/baseline configuration.
`compute --check` can gate on drift; `--write` and `--interactive` can change configuration. Follow
the direct-instruction requirement above. See [scanner] and [compute].

`dispat run <script>` executes configured work in changed packages. Its `--since` and `--consumers`
options describe a script sweep, not release-preview flags; check [run help][run] before using them.
`github`, `commit`, `writer`, `replacer`, the auto-edit commands, script helpers, `install`, and
`self-update` can mutate state or execute code. Being outside `command.dispat.release` is not an
allow decision or a reason to use them as an alternative route around a release approval.

This guidance was checked against Dispat commit
[`909dc401f3725a610604b77b0e790808cee9a524`](https://github.com/yohimik/dispat/tree/909dc401f3725a610604b77b0e790808cee9a524).
The `dispat release` implementation (also used by bare `dispat`) acquires the lock before planning,
including with `--require-release`, as described in the dedicated lock documentation.
`dispat status --require-release` remains a lock-free status gate. Older wording in some CLI/CI
pages describes a pre-lock empty-plan check and should not be used as a release-preview guarantee.
Consult installed-version help and the corresponding source when these descriptions differ.

[autowriter]: https://github.com/yohimik/dispat/blob/909dc401f3725a610604b77b0e790808cee9a524/packages/docs/docs/cli/autowriter.md
[ccme]: https://github.com/yohimik/dispat/blob/main/specs/ccme-spec/SPEC.md
[ccme-api]: https://github.com/yohimik/dispat/blob/main/packages/docs/docs/go/ccme.md
[change-scope]: https://github.com/yohimik/dispat/blob/main/packages/docs/docs/configuration/change-scope.md
[cli]: https://github.com/yohimik/dispat/blob/main/packages/docs/docs/cli/README.md
[commits]: https://github.com/yohimik/dispat/blob/main/packages/docs/docs/reference/commits.md
[compute]: https://github.com/yohimik/dispat/blob/main/packages/docs/docs/cli/compute.md
[configuration]: https://github.com/yohimik/dispat/blob/main/packages/docs/docs/configuration/README.md
[dependencies]: https://github.com/yohimik/dispat/blob/main/packages/docs/docs/configuration/dependencies.md
[diagnostics]: https://github.com/yohimik/dispat/blob/main/packages/docs/docs/reference/plan-errors.md
[dispat-package-config]: https://github.com/yohimik/dispat/blob/909dc401f3725a610604b77b0e790808cee9a524/services/dispat/dispat.yaml
[dispat-pkg-config]: https://github.com/yohimik/dispat/blob/909dc401f3725a610604b77b0e790808cee9a524/pkg/dispat.yaml
[dispat-pnpm]: https://github.com/yohimik/dispat/blob/909dc401f3725a610604b77b0e790808cee9a524/packages/docs/docs/examples/pnpm.md
[dispat-services-config]: https://github.com/yohimik/dispat/blob/909dc401f3725a610604b77b0e790808cee9a524/services/dispat.yaml
[dispat-test-dockerfile]: https://github.com/yohimik/dispat/blob/909dc401f3725a610604b77b0e790808cee9a524/Dockerfile.gotest
[dotenv]: https://github.com/yohimik/dispat/blob/main/packages/docs/docs/configuration/dotenv.md
[environment]: https://github.com/yohimik/dispat/blob/main/packages/docs/docs/configuration/env.md
[hooks]: https://github.com/yohimik/dispat/blob/main/packages/docs/docs/configuration/run-hooks.md
[lock]: https://github.com/yohimik/dispat/blob/main/packages/docs/docs/reference/releasing/release-lock.md
[packages]: https://github.com/yohimik/dispat/blob/main/packages/docs/docs/configuration/packages.md
[parser]: https://github.com/yohimik/dispat/blob/main/packages/docs/docs/configuration/parser.md
[partial]: https://github.com/yohimik/dispat/blob/main/packages/docs/docs/reference/releasing/partial-releases.md
[pnpm-workspaces]: https://pnpm.io/workspaces
[post-publish]: https://github.com/yohimik/dispat/blob/main/packages/docs/docs/internals/architecture.md#after-the-point-of-no-return
[preview]: https://github.com/yohimik/dispat/blob/main/packages/docs/docs/cli/preview.md
[records]: https://github.com/yohimik/dispat/blob/main/packages/docs/docs/configuration/records.md
[recovery]: https://github.com/yohimik/dispat/blob/main/packages/docs/docs/reference/releasing/recovery.md
[refs]: https://github.com/yohimik/dispat/blob/main/packages/docs/docs/configuration/refs.md
[release-ci]: https://github.com/yohimik/dispat/blob/909dc401f3725a610604b77b0e790808cee9a524/.github/workflows/release.yml
[run]: https://github.com/yohimik/dispat/blob/main/packages/docs/docs/cli/run.md
[scanner]: https://github.com/yohimik/dispat/blob/main/packages/docs/docs/cli/scanner.md
[scripts]: https://github.com/yohimik/dispat/blob/main/packages/docs/docs/configuration/scripts.md
[spaces]: https://github.com/yohimik/dispat/blob/main/packages/docs/docs/configuration/spaces.md
[stages]: https://github.com/yohimik/dispat/blob/main/packages/docs/docs/configuration/spaces.md#stages-and-hooks
[status]: https://github.com/yohimik/dispat/blob/main/packages/docs/docs/cli/status.md
[steps]: https://github.com/yohimik/dispat/blob/main/packages/docs/docs/reference/releasing/steps.md
[test-ci]: https://github.com/yohimik/dispat/blob/909dc401f3725a610604b77b0e790808cee9a524/.github/workflows/tests.yml
[trigger]: https://github.com/yohimik/dispat/blob/909dc401f3725a610604b77b0e790808cee9a524/packages/docs/docs/cli/trigger.md
[versions]: https://github.com/yohimik/dispat/blob/main/packages/docs/docs/configuration/versions.md
[webhooks]: https://github.com/yohimik/dispat/blob/909dc401f3725a610604b77b0e790808cee9a524/packages/docs/docs/configuration/webhooks.md
[writer]: https://github.com/yohimik/dispat/blob/909dc401f3725a610604b77b0e790808cee9a524/packages/docs/docs/cli/writer.md
