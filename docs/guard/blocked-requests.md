# Blocked requests

Guard defaults to **Find a safe alternative** for every harness. An action that
needs review is denied without opening a native permission questionnaire, a
browser approval page, or an MCP approval prompt. The agent receives the reason
and guidance to use a permitted alternative. It must preserve the protection,
avoid equivalent retries, and explain the limitation if it cannot finish safely.

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
