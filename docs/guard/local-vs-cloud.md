# Local Guard vs Guard Cloud

Guard protects your machine first. Guard Cloud is an optional paid service
providing cloud history, visibility, sync, and governance around that protection.

The product boundary is defined by
[ADR 0011: Extension-First Managed Controls](./adr/0011-extension-first-managed-controls.md)
and the [Managed Controls Product Glossary](./managed-controls-glossary.md).

## Local Guard baseline

Available without a Cloud subscription or sign-in:

- **Launch interception and wrappers** - `hol-guard install` and `hol-guard run`
  sit in front of supported AI harnesses before tools, MCP servers, or skills
  execute.
- **Local Extensions, settings, and remembered decisions** - built-in Extension
  permissions, home config, project overrides, and remembered allow or deny
  decisions resolve on this machine. Saved local decisions are verified against
  Guard-maintained integrity key material before they become authoritative
  again.
- **Local blocking and warnings** - Guard can stop or warn on supported risky
  shell commands, file reads, MCP tool calls, skill loads, and prompt-sensitive
  actions before side effects occur.
- **Package-manager protection where supported** - supported managers, including
  npm and PyPI, can be intercepted locally through shims and runtime evaluation.
  Unsupported or monitor-only managers stay advisory only.
- **Local receipts and explain output** - `hol-guard receipts`, `hol-guard
  explain`, and the local approval center record what Guard decided and why.
- **Local approval and review paths** - inline harness approval, the local
  approval center on `127.0.0.1`, and `hol-guard approvals` resolve decisions
  without Cloud.
- **Local decision-integrity tooling** - `hol-guard policies verify`,
  `integrity-status`, `migrate-local-integrity`, and `repair --clear-invalid`
  retain their compatibility names and let an operator detect unsigned,
  unknown-key, or tampered local decision rows.
- **Cloud-outage independence** - if Guard Cloud is unavailable, you are signed
  out, your trial ends, a subscription is past due or canceled, or you never
  connected, local interception, Extensions, blocking, receipts, and approvals
  continue on the machine.

Guard does not meter local safety features. You can detect harnesses, install
launchers, configure Extensions, diff changes, prompt for approval, and inspect
receipts without signing in.

Safe Decode runs locally too. It inspects encoded payload layers for review
evidence, but never executes decoded payloads and only syncs redacted summaries
when optional Cloud receipt sync is enabled.

## Guard Cloud for individual developers

Guard Cloud is a personal AI safety cockpit and governance layer. It does not
gate baseline local protection.

### Solo

Solo is the personal continuity tier for one developer. It adds Cloud value
without changing what Guard can protect locally:

- Cloud receipt and decision-memory sync for **two Cloud-connected devices**
- **30 days** of searchable Cloud history
- **1 GB** of Cloud storage
- basic history search
- a weekly personal security digest
- matched critical advisory email
- individual receipt download and a retained-history basic CSV/JSON export
- read-only Extension posture visibility for connected devices

The two-device limit is a Cloud-sync limit only. A third machine still installs,
intercepts, prompts, blocks, and writes local receipts normally. If the Portal
returns `device_limit_reached` or `cloud_sync_paused_plan_limit`, the client must
report Cloud sync as limited while continuing to report local protection
accurately.

### Pro

Pro remains the personal power-user tier. Portal-provided entitlements are the
source of truth, but the product boundary includes longer history and storage,
all supported personal-device Cloud continuity subject to the current service
policy, real-time alerting, personal Control Sets, simulation, version history,
rollout, rollback, acknowledgement, advanced search, and full evidence export.
The local client does not hardcode plan prices or use plan names as enforcement
logic.

### Cloud error contract

Cloud clients consume machine-actionable plan errors rather than parsing human
messages. Known normal plan boundaries include:

- `feature_not_in_plan`
- `device_limit_reached`
- `retention_limit_reached`
- `storage_limit_reached`
- `subscription_past_due`
- `trial_expired`
- `cloud_sync_paused_plan_limit`

These codes describe Cloud state only. A network outage, billing state, trial
state, retention limit, storage limit, or device limit must never be translated
into "protection expired," "device blocked," or another claim that local Guard
stopped working.

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

Team plans add shared ownership, managed Control Sets, routing, RBAC, billing,
and evidence exports on top of the individual Cloud value:

- **Shared workspaces** with members, roles, service principals, and ownership
- **Managed controls** with Extension targeting, simulation, review, staged
  rollout, acknowledgement, drift, rollback, and audit evidence
- **Shared review workflow** with assignment, SLA, remembered decisions, cases,
  exceptions, and audit history
- **Integrations** - Slack, GitHub, Jira, PagerDuty, email, and webhooks where
  setup and delivery are available
- **Team Package Firewall visibility** and exception governance
- **Billing, plan limits, admin controls, exports, and enterprise materials**

A `managed-restrictive` Control Set is limited in release 3.0 to disabling an
Extension, disabling a permission, or activating global lockdown. It is
separately negotiated and cannot be weakened by local remembered decisions.
Local tightening remains valid.

## Quick comparison

| Capability | Local Guard | Solo Cloud | Pro Cloud | Team Cloud |
| --- | --- | --- | --- | --- |
| Launch interception and Local Extensions | Included | Included | Included | Included |
| Local blocking and warnings on supported actions | Included | Included | Included | Included |
| Local receipts and approvals | Included | Included | Included | Included |
| Works when Cloud is offline | Yes | Local protection continues; sync pauses | Local protection continues; sync pauses | Local protection continues; sync pauses |
| Cloud-connected personal devices | None required | 2 | Portal entitlement | Managed by workspace |
| Cloud history | None required | 30 days | Portal entitlement | Workspace policy |
| Decision memory across machines | No | Included | Included | Included |
| Read-only Extension posture | Local only | Included | Included | Included |
| Personal Control Sets | No | No | Included | Included |
| Managed-restrictive Control Sets | No | No | No | Included |
| Real-time Cloud activity alerts | No | Not included | Portal entitlement | Team routing |
| Full evidence bundles | Local export only | Not included | Portal entitlement | Team evidence |
| Team RBAC, routing, and shared governance | No | No | No | Included |

## Related docs

- [Extension-First Managed Controls ADR](./adr/0011-extension-first-managed-controls.md)
- [Managed Controls Product Glossary](./managed-controls-glossary.md)
- [Local Extensions and protection settings](./managed-controls-local-extensions.md)
- [Managed Controls release notes](./managed-controls-release-notes.md)
- [Managed Controls support runbook](./managed-controls-support-runbook.md)
- [Get started](./get-started.md)
- [Harness support](./harness-support.md)
- [Remediation](./remediation.md)
