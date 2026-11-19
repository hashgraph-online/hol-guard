# Claude Code session modes

Guard protects Claude Code through hooks that `hol-guard install claude-code`
writes to the user settings file, `~/.claude/settings.json`. A Claude Code
session is protected only when it loads those user settings. This page lists
each way of starting Claude Code and whether Guard's hooks run in it.

## Modes

| How the session starts | Guard hooks | Status |
| --- | --- | --- |
| Interactive terminal (`claude`) | Loaded from user settings | Protected |
| Headless (`claude -p`), any `--permission-mode` | Loaded from user settings | Protected, live-tested |
| Background (`claude --bg`) | Loaded from user settings | Hooks run; not qualified with Guard |
| `claude --bare` | Skipped | Not protected |
| `--setting-sources` without `user` | Skipped | Not protected |
| Agent SDK with `settingSources` that leaves out `"user"` | Skipped | Not protected |

"Protected" holds only while Claude Code runs Guard's hooks from user settings.
`disableAllHooks: true` in effective settings, or `allowManagedHooksOnly: true` in
managed settings, stops them even though user settings load. See
[Settings that turn Guard's hooks off](claude-code-settings.md#settings-that-turn-guards-hooks-off).

### Headless

The Gauntlet Claude Code lane runs Claude Code with `-p`,
`--permission-mode bypassPermissions` and `--setting-sources user`. A live run
of its secret-write cases on Claude Code 2.1.325 denied each write before it
ran and left no file behind. That lane is not part of core release
qualification, which drives Oh My Pi only, so each release does not re-prove
it.

A Guard review renders as `permissionDecision: "ask"` for Claude Code. In a
headless run nobody can answer that question, so Claude Code refuses the tool
call and lists it under `permission_denials` in the result. Claude Code 2.1.325
was checked in `bypassPermissions`, `acceptEdits` and `default` modes, with the
tool also listed in `--allowedTools`; the tool did not run in any of them. A
review in a headless run therefore stops the action, the same as a block.

### Background

`claude --bg` sessions load the same user settings, and the hooks run. A
review waits at Claude Code's confirmation prompt until someone attaches to the
session with `claude attach` and answers it; the tool does not run while it
waits. No Guard qualification lane drives background sessions yet, so the
harness claims list them as a known blind spot rather than as protected.

### Sessions that skip user settings

`--bare` skips hooks defined in settings and by plugins. `--setting-sources` and
the Agent SDK's `settingSources` option choose which settings files load; when
the list leaves out `user`, Guard's hooks are not loaded. Claude Code gives no
signal that Guard is absent in these sessions. Run them only on work you would
run without Guard, or add `user` to the setting sources.

## Source of the claims

The harness claims in [harness-claims.md](harness-claims.md) are generated from
the harness protection contract; this page explains the Claude Code blind
spots that contract names.
