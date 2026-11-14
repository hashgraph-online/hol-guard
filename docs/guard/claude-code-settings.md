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

Hooks are always written to the user settings file, even when you install from a workspace. The workspace
only scopes the hook URL and the Guard policy. Install says so in its output.

Guard does not write `.claude/settings.json` or `.claude/settings.local.json` in a project, managed
settings, or `~/.claude.json`. It reads project files for inventory and for the workspace hook scan.

## Entries Guard treats as its own

A hook handler is Guard's when one of these holds:

- a `command` handler (or one with no `type`) whose command, or any `args` element, contains
  `HOL_GUARD_CLAUDE_DAEMON_HOOK` or `HOL_GUARD_CLAUDE_SESSION_START_HOOK`;
- a `command` handler from an older build that runs `codex_plugin_scanner.cli` with `guard hook`, or calls
  `ensure_guard_daemon(` with the Guard session context;
- an `http` handler whose URL starts with `http://127.0.0.1:` and contains `/v1/hooks/claude-code`.

Every other handler, matcher group, event and top-level setting is left as it was.

## Install and refresh

Install and the `SessionStart` refresh make the same edit:

1. Read `~/.claude/settings.json`. A missing file starts empty. A file that is not JSON, or not a JSON
   object, stops the install with an error, and Guard does not rewrite it.
2. In each event Guard manages, remove Guard's handlers, then add one Guard handler per matcher:
   - `SessionStart` with matchers `startup`, `resume`, `clear` and `compact`;
   - `PreToolUse`, `PermissionRequest`, `PostToolUse`, `Notification` (`permission_prompt`), `Stop` and
     `UserPromptSubmit`.
3. Remove Guard's handlers from retired events (`PermissionDenied`), and drop a retired event left empty.
4. Write the file with its original mode. A new file is created as `0644`.

The refresh runs on each `SessionStart`. After a Guard upgrade it rewrites the handlers with the new
build's command line, so they do not keep pointing at an old build.

If Guard's entries go missing while setup is `active`, doctor reports the setup as `broken` and names the
missing events. Run `hol-guard repair` or `hol-guard install claude-code` to restore them.

## Removal

`hol-guard uninstall claude-code`:

- removes Guard's handlers from `SessionStart`, `PreToolUse`, `PermissionRequest`, `PostToolUse`,
  `UserPromptSubmit`, `Notification` and `Stop`, and from the retired events;
- writes each of those events back, as an empty list when no other handler is left. It does this even
  for an event that was not in the file before;
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

Two settings can stop Claude from running Guard's handlers:

- `disableAllHooks: true` in any settings file Claude reads;
- a managed policy that lets only managed hooks run.

Guard does not detect either setting yet. Doctor can then report Guard's entries as present while Claude
ignores them. Treat a Claude Code protection state as proven only from a live block on the same machine.

A project's own hooks run alongside Guard's. They do not replace them. The workspace hook scan reviews
hook commands it finds in the project's `.claude/settings.json` and `.claude/settings.local.json`.
