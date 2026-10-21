# Blocked requests

Guard defaults to **Find a safe alternative** for every harness. An action that
needs review is denied without opening a native permission questionnaire, a
browser approval page, or an MCP approval prompt. The agent receives the reason
and guidance to use a permitted alternative. It must preserve the protection,
avoid equivalent retries, and explain the limitation if it cannot finish safely.

The denial is still recorded. The inbox keeps the pending review, and that same
write is what analytics and cloud review use for later policy. Recording does
not open a prompt and does not tell the agent to ask for approval. If the inbox
write fails, the action stays blocked.

In **Settings → Approval gate → When Guard blocks a request**, select **Ask me
for approval** to restore approval prompts. The existing ask-surface setting
then selects where prompts appear. Hard blocks and sandbox requirements remain
enforced in either mode. Previously authorized, valid approvals still follow
the existing scope, expiry, and replay checks. Watch mode keeps recording without
stopping actions.

The device setting is `blocked_request_mode = "safe-alternative"` (default) or
`blocked_request_mode = "ask"` in the local Guard configuration. Workspace
configuration cannot opt the user into prompts. Existing installations with no
explicit value receive the new default.

## What runs contained

A command Guard cannot prove safe on its own can still run inside the
protected workspace sandbox. The contained-run reason and the note a failed
contained run prints say so, so an agent can plan around it:

- Guard runs a command it proves safe directly, outside the sandbox.
- A contained command and every program it starts, including children of an
  interpreter such as `node`, `python` or a shell script, can write only the
  workspace, `$TMPDIR` and a private scratch `$HOME` that is not your real home
  directory. They have no network, no access to your home directory, no
  pseudo-terminal and no Docker socket.
- When a contained command fails on one of those limits, the note names the
  limit that was hit (a write, a program start, the network, a read, a PTY or
  the Docker socket). The limits stay denied; use a non-interactive form of
  the command, or keep what it needs inside the workspace.
