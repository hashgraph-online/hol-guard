# Install a plugin from HOL

`hol-guard plugin install <owner/plugin>` installs a plugin listed on HOL with each runtime's own CLI: `claude` for Claude Code and `codex` for Codex. Before it runs anything, Guard reads HOL's scan result for the listing and stops when that result asks it to. `hol-guard plugin uninstall` removes what `install` added.

Both commands need HOL Guard 3.58.0 or later with its native runtime. If `plugin install` says the native runtime is missing, run `hol-guard update`; see [Get started](get-started.md#platform-support).

## Read the plan first

Without `--apply`, Guard only prints what it would do. Nothing on your machine changes.

```text
$ hol-guard plugin install acme/toolgate
acme/toolgate 1.0.0 on HOL
  Security  Passed HOL's checks.
            Scanned 2026-10-26 at d0f1678: 0 critical, 0 high.
            Report: https://hol.org/registry/plugins/acme%2Ftoolgate
  Trust     82/100
  Listing   https://hol.org/registry/plugins/acme%2Ftoolgate

What Guard will run. Nothing has changed yet.

  Claude Code   /usr/local/bin/claude
  claude plugin marketplace add acme/toolgate
  claude plugin install toolgate@acme
  Undo: hol-guard plugin uninstall acme/toolgate --apply --runtime claude-code

  Codex         /usr/local/bin/codex
  codex plugin marketplace add acme/toolgate --ref d0f16789124e9a5ebde476bf16f72920e1a9d804
  codex plugin add toolgate@acme
  Undo: hol-guard plugin uninstall acme/toolgate --apply --runtime codex

  Other agents  Guard does not run this. To do it yourself:
  npx skills@1.7.4 add acme/toolgate
  Run this yourself: the Skills CLI downloads a package from npm and installs
  for every agent it detects.

Run again with --apply. Guard asks before each runtime.
```

The plan shows the scan result first, then each runtime Guard found, the full path of the program it will run, the exact commands and how to undo them. Runtimes Guard cannot run itself, such as other agents through the Skills CLI, get a command to run yourself.

## Install

```bash
hol-guard plugin install acme/toolgate --apply
```

Guard asks before each runtime, runs the commands, then reads the runtime's own plugin list to check the plugin is there:

```text
$ claude plugin marketplace add acme/toolgate
$ claude plugin install toolgate@acme
claude-code: installed; start a new session to load it. Check with: claude plugin list
$ codex plugin marketplace add acme/toolgate --ref d0f16789124e9a5ebde476bf16f72920e1a9d804
$ codex plugin add toolgate@acme
codex: installed; start a new session to load it. Check with: codex plugin list
```

Use `--runtime claude-code` or `--runtime codex` to install for one runtime only. In CI, `--yes` skips the per-runtime question. `--yes` never accepts a scan warning or an install command the plugin declares; those need the flags below.

## What stops an install

| HOL's scan result | What Guard does |
| :--- | :--- |
| Passed | Installs after your confirmation. |
| Warnings, no scan yet, or an old scan | Asks you in the terminal. With `--yes`, it stops unless you also pass `--accept-risk`. |
| Blocked, or the listing is held | Refuses and prints the reason and the report link. `--accept-risk` does not override it. |

Guard installs the commit HOL scanned. Codex is pinned to it with `--ref`. Claude Code cannot pin a commit, so Guard checks the installed commit afterwards and removes the plugin again if it differs from the scanned one.

Some Claude Code plugins install by running a command the plugin declares. Guard shows that command and its sha256 and runs it only when you answer yes in the terminal, or when you pass `--accept-command <sha256>` with the matching value.

Guard runs only `claude` and `codex` programs it finds in absolute `PATH` folders or in each runtime's standard install location. It skips relative `PATH` entries such as `.` and, on macOS and Linux, folders every user can write to, and says which copy it skipped.

## Uninstall

```bash
hol-guard plugin uninstall acme/toolgate --apply
```

Guard removes the plugin with each runtime's own command. It also removes a marketplace that Guard added for this plugin, unless another plugin still uses it. A marketplace you added yourself stays.

## Check an installed plugin

```bash
hol-guard plugin verify acme/toolgate
```

HOL records, for every listing version, the commit each channel served: its own catalog, Claude Code's official marketplace, Open VSX and the others it watches. `verify` reads the version and commit Claude Code recorded for your user-scope install of the listing and compares them with that record.

- **Matches**: the commit Claude Code installed is one HOL recorded for that version.
- **Warning**: HOL recorded a different commit for that version. Guard prints the commits it recorded, any notes such as a re-tagged or withdrawn version, and the listing's releases page. It changes nothing: the plugin stays installed and enabled, and the command exits 0.
- **Nothing to compare**: HOL has no commit for that version yet, or Claude Code kept no commit, as for a plugin installed by running a declared command.

Exit codes: 0 when the check ran, whatever it found; 2 for a usage error or an answer HOL should not have sent; 3 when Claude Code has no install of the listing for your user or HOL has no integrity record for it; 6 when HOL is unreachable. `--json` prints one `hol-guard.plugin-verify/1` document with `status` set to `matches`, `differs`, `not_recorded` or `no_commit`.

`verify` sends two HTTPS `GET`s: the listing's install spec, then its public integrity record from the same origin. Only the listing name is sent; your installed version and commit stay on your machine. `HOL_GUARD_PLUGIN_SPEC_URL` moves both requests to your own portal.

## Exit codes

| Code | Meaning |
| :--- | :--- |
| 0 | Done, or plan shown |
| 1 | A runtime command or the post-install check failed |
| 2 | Usage error, a listing that is not on HOL or was removed, or no terminal to confirm in |
| 3 | Nothing Guard can install here |
| 4 | Stopped by HOL's scan result, a commit other than the scanned one, or a declared command not accepted |
| 5 | This Guard is too old for the listing |
| 6 | HOL unreachable |
| 130 | Interrupted |

`--json` prints one `hol-guard.plugin-install/1` document on stdout with the plan and each runtime's outcome; everything else goes to stderr.

## What Guard sends to HOL

One request per run: an HTTPS `GET` of the listing's install spec, with the listing name and spec version in the query and `hol-guard/<version>` as the user agent. It waits 10 seconds and retries once after a timeout or a server error. Nothing about you, your machine or your installed plugins is sent. `--spec-file` reads the spec from a file instead, with no request.

Install counts for plugin authors are separate, off by default and described in [Plugin install counts](plugin-telemetry.md).

Guard keeps a record of what it installed in `plugin-kit/installs.json` in the Guard home, readable only by you. `uninstall` uses it to know which marketplaces Guard added.

## Platforms

Tested on macOS (Apple silicon and Intel), Linux (x86_64 and ARM64) and Windows x64. Windows ARM64 is not tested yet.

## Test against your own portal

Set `HOL_GUARD_PLUGIN_SPEC_URL` to an install-spec URL (https, or http on localhost). Guard prints a warning on every run while it is set, and the listing and report links must come from that same origin.
