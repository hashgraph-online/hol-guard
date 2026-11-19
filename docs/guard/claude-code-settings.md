# Claude Code settings: what Guard owns and how it is removed

This page lists the Claude Code files Guard writes, the entries it treats as its own, and how install,
upgrade and removal change them. The native runtime does the work in
`rust/crates/guard-runtime/src/adapters/harness_adapter/claude.rs` and `claude_settings.rs`. The hook
groups come from `src/codex_plugin_scanner/guard/contracts/claude-hook-groups.v1.json`.

## Files Guard writes

| File | Written by | What Guard changes |
|---|---|---|
| `~/.claude/settings.json` | `hol-guard install claude-code`, the `SessionStart` refresh, `hol-guard uninstall claude-code`, `hol-guard hooks remove --all` | Guard's handlers inside the `hooks` object only |
| `~/.hol-guard/bin/guard-claude-code` (`.cmd` on Windows) | install | The launcher shim. Guard owns the whole file |
| `<guard-home>/backups/hook-removal-<UTC stamp>/` | `hooks remove --all` | Copies of every config file it edited |
| `.claude/settings.json` and `.claude/settings.local.json` in the current workspace | `hooks remove --all` only | Removes Guard's handlers, after a backup |

Hooks are always written to the user settings file, even when you install from a workspace. The workspace
only scopes the hook URL and the Guard policy. Install says so in its output.

Before it writes anything, `hol-guard install claude-code --dry-run` (and `hol-guard apps connect
claude-code --dry-run`) prints a **Claude Code settings** panel with:

- the one file Guard writes and its scope (`user`);
- with `--workspace`, a line saying the project's `.claude` directory is not written;
- every settings file Claude Code reads, highest precedence first, with Guard's file marked;
- that headless `claude -p` and Remote Control sessions, which run on this machine, read the same file,
  that cloud sessions (Claude Code on the web) do not, that sessions started with `--bare` or with
  setting sources that leave out `user` skip Guard's hooks, and that background sessions
  (`claude --bg`) run them but are not qualified with Guard (see
  [Claude Code session modes](claude-code-sessions.md));
- the undo command, `hol-guard uninstall claude-code`, and what it removes. When the install used `--home` or `--guard-home`, the printed command carries the same options, so it undoes this install and not another one;
- a warning for each setting that would stop Claude Code running Guard's hooks (see
  [Settings that turn Guard's hooks off](#settings-that-turn-guards-hooks-off)). Install reads only the
  managed and user settings files, the project files when you pass `--workspace`, and its own
  environment. It cannot warn about a setting passed when a session starts, such as
  `claude --settings '{"disableAllHooks": true}'`. For `disableAllHooks` it reports the value from the
  highest-precedence file that sets it, as Claude Code does;
- on Windows, the undo command is quoted for PowerShell.

The real install repeats the file, the undo command and any warning in its notes.

Guard does not follow `CLAUDE_CONFIG_DIR`. It writes `~/.claude/settings.json` under your home directory
even when that variable is set. If Claude Code runs with `CLAUDE_CONFIG_DIR` pointing elsewhere, it does
not read the file Guard wrote, and Guard's hooks do not run. Install warns when the variable is set in its
own environment and points somewhere else; it cannot see a value set only in the shell that starts Claude.

Install, refresh and uninstall never write a project's `.claude/settings.json` or
`.claude/settings.local.json`, managed settings, or `~/.claude.json`. Guard reads project files for
inventory and for the workspace hook scan. The one exception is `hol-guard hooks remove --all`: it removes
Guard's handlers from the current workspace's `.claude/settings.json` and `.claude/settings.local.json`
when they contain any, after backing them up (see [Removal](#removal)).

## Entries Guard treats as its own

A hook handler is Guard's when one of these holds:

- a `command` handler (or one with no `type`) whose command, or any `args` element, contains
  `HOL_GUARD_CLAUDE_DAEMON_HOOK` or `HOL_GUARD_CLAUDE_SESSION_START_HOOK`;
- a `command` handler from an older build that runs `codex_plugin_scanner.cli` with `guard hook`, or calls
  `ensure_guard_daemon(` with the Guard session context;
- an `http` handler whose URL starts with `http://127.0.0.1:` and contains `/v1/hooks/claude-code`.

Every other handler, matcher group, event and top-level setting is left as it was.

## Install and refresh

Install makes this edit:

1. Read `~/.claude/settings.json`. A missing file starts empty. A file that is not JSON, or not a JSON
   object, stops the install with an error, and Guard does not rewrite it.
2. In each event Guard manages, remove Guard's handlers, then add one Guard handler per matcher:
   - `SessionStart` with matchers `startup`, `resume`, `clear` and `compact`;
   - `PreToolUse`, `PermissionRequest`, `PostToolUse`, `Notification` (`permission_prompt`), `Stop` and
     `UserPromptSubmit`.
3. Remove Guard's handlers from retired events (`PermissionDenied`), and drop a retired event left empty.
4. Write the file with its original mode. A new file is created as `0644`.

On each `SessionStart`, Guard checks whether its installed handlers already match what this build would
write. When they match, nothing is written. When they do not, for example after a Guard upgrade, the
refresh rewrites Guard's handlers with steps 2 and 3, so they do not keep pointing at an old build.

The refresh repairs less than install does:

- it does nothing when the file is missing or has no `hooks` object;
- it reads the file leniently and does not stop with an error on a file that is not a JSON object.

Run `hol-guard install claude-code` to recreate missing entries.

Doctor checks two events. If Guard's `PreToolUse` or `PermissionRequest` handler is missing while setup is
`active`, doctor reports the setup as `broken` and names the missing event. It does not check the other
events, so a missing `UserPromptSubmit` or `Stop` handler is not reported. Run `hol-guard repair` or
`hol-guard install claude-code` to restore them.

## Removal

`hol-guard uninstall claude-code`:

- removes Guard's handlers from `SessionStart`, `PreToolUse`, `PermissionRequest`, `PostToolUse`,
  `UserPromptSubmit`, `Notification` and `Stop`, and from the retired events;
- keeps every other handler on those events, and removes an event Guard's removal leaves empty, so
  the file holds no empty list the user never had. When no event is left, it removes the `hooks`
  object as well;
- does nothing to the file when it has no `hooks` object, or when it cannot be read as a JSON object.
  The second case leaves any Guard entries in place; `hooks remove --all` reports them;
- removes the launcher shim and marks the install inactive.

This command makes no backup, because it only removes Guard's own handlers.

`hol-guard hooks remove --all` is the backstop for handlers Guard no longer has a record of:

1. Copy every candidate file to `<guard-home>/backups/hook-removal-<UTC stamp>/`. If a file cannot be
   copied, Guard skips that harness and does not edit it.
2. Run the adapter uninstall above.
3. Run the native sweep over `~/.claude/settings.json`, `~/.claude/settings.local.json` and, for the
   current workspace, `.claude/settings.json` and `.claude/settings.local.json`. It removes Guard's
   handlers only.
4. Drop backup copies of files that did not change, then scan again and report any Guard handlers left.

To restore a file, copy it back from the backup directory. To put Guard back, run
`hol-guard install claude-code`.

## How Claude Code combines settings

Claude Code reads hooks from managed, user, project and local settings and runs the handlers from all of
them together. Guard relies only on the user file. It does not raise its own precedence.

### Settings that turn Guard's hooks off

Two settings can stop Claude from running Guard's handlers:

- `disableAllHooks: true` in the highest-precedence settings file that sets the key (a project `false`
  overrides a user `true`);
- `allowManagedHooksOnly: true` in managed settings, which lets only managed hooks run.

Install reads, and never writes, the managed settings file (`/Library/Application Support/ClaudeCode/`
on macOS, `/etc/claude-code/` on Linux, `%ProgramFiles%\ClaudeCode\` on Windows, each
`managed-settings.json`), the user file, and, with `--workspace`, the project's `settings.json` and
`settings.local.json`. It warns for each of these settings that takes effect. A file that is missing, unreadable,
not JSON, not a regular file or larger than 1 MiB is not reported. Doctor does not run this check, so it can still report Guard's entries as
present while Claude ignores them. Treat a Claude Code protection state as proven only from a live block
on the same machine.

A project's own hooks run alongside Guard's. They do not replace them. The workspace hook scan reviews
hook commands it finds in the project's `.claude/settings.json` and `.claude/settings.local.json`.

Sessions started with `--bare`, or with setting sources that leave out `user`, never load Guard's
hooks. See [Claude Code session modes](./claude-code-sessions.md) for each way of starting Claude Code.
