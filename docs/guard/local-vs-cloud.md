# Local Guard vs Guard Cloud

Guard protects your machine first. Guard Cloud is an optional paid service
providing cloud history, visibility, sync, and management around that protection.

## Local Guard baseline

Available without a Cloud subscription or sign-in:

- **Launch interception and wrappers** — `hol-guard install` and `hol-guard run`
  sit in front of supported AI harnesses before tools, MCP servers, or skills
  execute.
- **Local policy decisions** — home config, project overrides, saved allow/deny
  rules, and built-in recommendations resolve on this machine. Saved local
  decisions are verified against Guard-managed integrity key material before
  they become authoritative again.
- **Local blocking and warnings** — Guard can stop or warn on supported risky
  shell commands, file reads, MCP tool calls, skill loads, and prompt-sensitive
  actions before side effects occur.
- **Package-manager protection where supported** — supported managers (for
  example npm and PyPI) can be intercepted locally through shims and runtime
  evaluation. Unsupported or monitor-only managers stay advisory only.
- **Local receipts and explain output** — `hol-guard receipts`, `hol-guard
  explain`, and the local approval center record what Guard decided and why.
- **Local approval and review paths** — inline harness approval, the local
  approval center on `127.0.0.1`, and `hol-guard approvals` resolve decisions
  without Cloud.
- **Local policy integrity tooling** — `hol-guard policies verify`,
  `integrity-status`, `migrate-local-integrity`, and `repair --clear-invalid`
  let an operator detect unsigned, unknown-key, or tampered local policy rows
  and move to enforce mode deliberately.
- **Cloud-outage independence** — if Guard Cloud is unavailable, you are signed
  out, or never connected, local interception, policy, blocking, receipts, and
  approvals continue on the machine.

Guard does not meter local safety features. You can detect harnesses, install
launchers, diff changes, prompt for approval, and inspect receipts without
signing in.

Safe Decode runs locally too. It inspects encoded payload layers for review
evidence, but never executes decoded payloads and only syncs redacted summaries
when optional Cloud receipt sync is enabled.

## Guard Cloud for individual developers

Guard Cloud is a personal AI safety cockpit and memory layer. It does not gate
baseline local protection.

Paid Cloud value for a solo developer or vibe coder includes:

- **Synced history** across sessions, devices, and hosted or local agents
- **Searchable activity** — blocked actions, approvals, package installs,
  MCP/Skill changes, and risky activity in one timeline
- **Decision memory and policy suggestions** — safe repeated choices stop
  becoming repeated interruptions
- **MCP/Skill drift visibility over time** — changed schemas, commands,
  transports, scopes, and dependencies stay visible after first trust
- **Incident-style summaries** — what happened, why it mattered, and what to
  do next without digging through raw logs
- **Cloud Firewall UI** — package risk, feed freshness, remediation guidance,
  and safer fix paths on top of local enforcement
- **Exports and shareable records** — audit-ready evidence packages when you
  need to show what Guard handled
- **Digests and notifications** — calm routing for what needs attention

Optional Cloud pairing commands:

```bash
hol-guard connect
hol-guard connect status
hol-guard connect repair
hol-guard sync
hol-guard supply-chain sync
```

`hol-guard connect` is the canonical way to pair a machine with Guard Cloud.
`hol-guard connect --headless` uses OAuth Device Code for SSH/CI hosts.
`hol-guard login` remains only as a redirecting compatibility alias. These
commands add sync and visibility; they do not unlock core local protection.

Pairing also does not authorize Cloud commands on the device. That channel is
off by default and separate from read-only synchronization. Inspect its status
or opt into the read-only operation set explicitly:

```bash
hol-guard commands status
hol-guard commands enable --operations read-only
hol-guard daemon repair
```

Capabilities are signed, device/workspace-bound, limited to exact operations,
and expire. State-changing jobs remain paused for one-job local approval. Use
`hol-guard commands revoke --confirm revoke` to disable commands immediately
without disconnecting Cloud sync. See the full
[Cloud command capability contract](./cloud-command-capability.md).

## Guard Cloud for teams

Team plans add shared ownership, routing, RBAC, billing, and evidence exports
on top of the individual Cloud value:

- **Shared workspaces** with members, roles, service principals, and ownership
- **Shared review workflow** with assignment, SLA, policy memory, cases, and
  audit history
- **Integrations** — Slack, GitHub, Jira, PagerDuty, email, and webhooks where
  setup and delivery are available
- **Team package firewall visibility** and exception governance
- **Billing, plan limits, admin controls, exports, and enterprise materials**

## Quick comparison

| Capability | Local Guard | Guard Cloud |
| --- | --- | --- |
| Launch interception and local policy | Included | Included |
| Local blocking/warnings on supported actions | Included | Included |
| Local receipts and approvals | Included | Included |
| Works when Cloud is offline | Yes | Local protection continues; sync pauses |
| Cross-device history and search | Device-local only | Included on paid plans |
| Decision memory across machines | No | Included on paid plans |
| Cloud Firewall UI and exports | No | Included on paid plans |
| Team RBAC, routing, and shared policy | No | Team plans |

## Related docs

- [Get started](./get-started.md)
- [Harness support](./harness-support.md)
- [Remediation](./remediation.md)
