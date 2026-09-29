# Devin adapter

Devin is Cognition's agentic CLI/IDE harness. Guard can protect Devin
sessions through Devin's own hook files; no plugin publishing flow is
required.

## What Guard detects

The Devin adapter (`hol-guard install devin`) scans:

- `~/.config/devin/config.json` — user hooks (under `hooks`) and legacy
  `mcpServers`. On Windows this resolves to
  `%APPDATA%\devin\config.json` instead.
- `~/.config/devin/mcp_config.json` — user MCP servers (under
  `mcpServers`, with `command`/`args`/`env` or `url`/`transport`).
- `.devin/config.json` and `.devin/config.local.json` — project hooks
  and legacy MCP servers.
- `.devin/hooks.v1.json` — project hooks; the entire file is the hooks
  object.
- `.devin/mcp_config.json` and `.devin/mcp_config.local.json` — project
  MCP servers.
- Skills under `.devin/skills/<name>/SKILL.md` and
  `.agents/skills/<name>/SKILL.md`, at both project and
  `~/.config/devin/` / `~/.agents/` user scope.
- Guard-managed Claude Code hooks in `.claude/settings.json`,
  `.claude/settings.local.json`, `~/.claude.json`, and
  `~/.claude/settings*.json` — surfaced as a warning, not an artifact.

Devin config files are JSONC (comments and trailing commas are allowed).
Guard reads them tolerantly for detection, but refuses to *rewrite* a
JSONC file during install — see "Install boundaries" below.

## What Guard installs

`hol-guard install devin` writes four Guard-managed hook groups into the
`hooks` section of `~/.config/devin/config.json`:

| Event | Matcher | Purpose |
| --- | --- | --- |
| `PreToolUse` | `^(exec\|read\|write\|edit\|apply_patch\|notebook_read\|notebook_edit\|grep\|glob\|webfetch\|mcp_call_tool\|mcp__.*)$` | Policy check before tool execution |
| `PermissionRequest` | same | Approval resolution for permission prompts |
| `UserPromptSubmit` | none (all prompts) | Prompt screening |
| `PostToolUse` | same | Observation after tool execution |

Each entry is a `type: "command"` hook that runs Guard's bounded CLI
bridge (`codex_plugin_scanner.cli guard hook --harness devin`) and carries
a `timeout`. Guard recognizes its own handlers by the bounded-bridge
command contents (and the legacy `# HOL_GUARD_MANAGED_DEVIN` marker
comment written by earlier versions) so it can distinguish them from
user hooks on reinstall and uninstall.

The matcher is a regex over `tool_name`; Devin treats an empty or absent
matcher as "match all tools". Guard's matcher covers Devin's file, shell,
search, web, and MCP tool names, including the direct
`mcp__<server>__<tool>` form.

Install preserves everything else in the config file: `permissions`,
`read_config_from`, `mcpServers`, and any pre-existing hooks entries. A
backup of the original file is stored once under
`<guard-home>/managed/devin/`, along with an `install.state.json`
recording the managed config path.

## How blocks surface in Devin

Devin blocks a tool call or prompt when the hook either exits with code
`2` or prints `{"decision":"block","reason":"..."}` on stdout. Guard
does both: deny decisions exit `2` and emit a Devin-native payload
containing `decision: "block"`, the reason, and a
`hookSpecificOutput.permissionDecision: "deny"` envelope.

Guard never emits `decision: "approve"` — that response auto-approves in
Devin, so allow paths emit no `decision` key at all.

Failures follow the bounded-bridge contract shared with the other
Claude-shaped adapters: malformed input or an explicit deny produces a
deny envelope with exit `2` (fail closed), while a timed-out or crashed
review emits a continue/allow envelope so a wedged Guard cannot stall
Devin. `PostToolUse` is observation-only and continues on failure.

Devin's own hook contract is the outer safety net: a hook process that
exits non-zero without using exit `2` or a `decision: "block"` payload is
logged by Devin but does not block the action.

## Claude Code hooks overlap

Devin also loads Claude Code hook files (`.claude/settings.json`,
`.claude/settings.local.json`, `~/.claude.json`,
`~/.claude/settings*.json`) when `read_config_from.claude` is true —
which is the default. If you also run `hol-guard install claude-code`,
Guard's Claude Code hooks will fire inside Devin sessions and events will
be attributed to Claude Code.

To attribute Devin activity only to the Devin adapter, set
`read_config_from.claude` to `false` in
`~/.config/devin/config.json`. Detection emits a warning when this
overlap is present and `read_config_from.claude` is not `false`;
install and uninstall leave the Claude hooks untouched either way.

## Install boundaries

Guard will not rewrite a JSONC config. If
`~/.config/devin/config.json` contains comments or trailing commas,
install fails with an error instead of producing a lossy rewrite.
Remove the comments (or move them to another file such as
`.devin/config.local.json`), then rerun `hol-guard install devin`.

## Uninstall and repair

- `hol-guard uninstall devin` removes only the Guard-managed handlers
  (identified by the marker), drops now-empty hook groups and an empty
  `hooks` object, removes the installed `devin` shim, and clears the
  managed state file. User hooks and other config keys are preserved.
- `hol-guard install devin` is idempotent — rerunning replaces the
  Guard-managed handler for each matcher rather than appending
  duplicates.
- `hol-guard repair devin` reinstalls missing managed entries without
  touching user hooks.
- `hol-guard doctor` reports Devin detection, managed-config state, and
  the Claude Code overlap warning.

## Known blind spots

- Devin loads Claude Code hook files by default, so Guard's Claude Code
  hooks may also run inside Devin sessions and attribute them to Claude
  Code (see above).
- Inline edits applied without a tool call, `write_to_process` input,
  and background shell output are not visible to Guard.
- Subagent tool calls are covered only where Devin fires hooks for them.
- `PostToolUse` observes but does not block; only `PreToolUse`,
  `PermissionRequest`, and `UserPromptSubmit` can deny.

## Commands

```bash
hol-guard install devin            # install hooks into ~/.config/devin/config.json
hol-guard install devin --dry-run  # preview without writing
hol-guard doctor                   # verify detection and hook state
hol-guard uninstall devin          # remove Guard-managed handlers only
```
