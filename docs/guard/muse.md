# Muse adapter

Muse is Meta's terminal coding agent (`muse`). Guard protects Muse
sessions through Muse's own settings hooks; no plugin publishing or
trust flow is required.

## What Guard detects

The Muse adapter (`hol-guard install muse`) inventories:

- `~/.config/muse/settings.json` (or `$XDG_CONFIG_HOME/muse/settings.json`)
  — user hooks under `hooks` and MCP servers under `mcpServers` (stdio
  `command` argv entries and streamable-HTTP `url` entries).
- Project `.muse/settings.json` — project hooks and MCP servers.
- Workspace `.muse-plugin/plugin.json` — plugin hook and MCP server
  capabilities declared by a project plugin manifest.
- Skills under `~/.config/muse/skills/`, `~/.agents/skills/`,
  `~/.claude/skills/`, and workspace `.agents/skills/` / `.muse/skills/`.
- Workspace skills also come from the shared AIBOM discovery that runs
  when Guard has a project workspace.

Detection runs in the Rust resident (`muse_detect`); Guard-managed hook
handlers are recognized and excluded from the user hook inventory.

## What Guard installs

`hol-guard install muse` writes six Guard-managed hook groups into the
`hooks` section of the user settings file:

| Event | Matcher | Purpose |
| --- | --- | --- |
| `PreToolUse` | none (all tools) | Policy check before tool execution |
| `PermissionRequest` | none (all tools) | Approval resolution for permission prompts |
| `UserPromptSubmit` | none (all prompts) | Prompt screening |
| `PostToolUse` | none (all tools) | Observation after tool execution |
| `SessionStart` | none | Guard context for the session |
| `Stop` | none | Session-stop observation |

No matcher is set on purpose: Muse reads an omitted matcher as every
tool, so shell, file read/write, search, web, MCP (`mcp__*`), and
package-manager calls all reach Guard. Package-manager shell and MCP
actions carry the same package intent, evidence, and supply-chain
decision flow as the other managed harnesses.

Each entry is a `type: "command"` hook that runs Guard's bounded CLI
bridge (`hol-guard hook --harness muse`) with a `timeout` and a
`statusMessage`. The `PreToolUse` and `PostToolUse` timeouts cover
Guard's configured approval wait plus a grace period, because an
approved call resumes inside the pending hook (see below).

Install preserves everything else in the settings file: `provider`,
`model`, `skills`, `mcpServers`, and any pre-existing hook entries. A
backup of the original file and an `install.state.json` are stored once
under `<guard-home>/managed/muse/`. Settings are strict JSON: Guard
refuses to rewrite a settings file that does not parse as a JSON object
instead of rewriting it lossily.

## How blocks surface in Muse

Muse hooks use the Claude-Code-shaped JSON contract (verified against
Muse 1.4.14 with `muse plugins hook test` and a live `muse exec` run):

- An allow is empty stdout with exit 0. Muse rejects a bare
  `permissionDecision: "allow"` without `updatedInput`, so Guard never
  emits one.
- A `PreToolUse` block is a `hookSpecificOutput.permissionDecision:
  "deny"` envelope with the reason, on exit 0 so Muse reads the JSON.
- A `UserPromptSubmit` block is `{"decision": "block", "reason": ...}`.
- `PostToolUse`, `SessionStart`, and `Stop` cannot undo or block a
  completed action; Guard adds `additionalContext` and otherwise stays
  silent.
- `PermissionRequest` defers to Muse's own approval prompt (no
  decision) while a review is pending; the `PreToolUse` verdict for the
  same call remains the decision boundary. A final block still denies.

Malformed hook input, a hook failure, or an unavailable Guard authority
fails closed before a protected tool runs; observation events continue
without authorizing anything.

## Approval resume

When Guard queues a `PreToolUse` review, the bounded bridge waits for
the approval inside the hook, the way Oh My Pi's managed extension does:
the user approves in the Guard approval center (or Muse's own prompt
where it applies), and the original tool call then proceeds unchanged —
no manual retry and no retyped command. A denial keeps the call
blocked. If the approval is still pending when the wait ends, Muse
shows the block; the saved Allow once / Always allow approval answers
the identical retry under the [approval invariant](./approval-invariant.md)
until the user removes it or the command's hash changes.

## Known blind spots

Guard manages hooks in the user settings file. Hooks contributed by
installed Muse plugins run beside Guard's and are inventoried but not
rewritten. Inline edits applied without a tool call, and background
shell output after a call returns, are not visible to Guard.
