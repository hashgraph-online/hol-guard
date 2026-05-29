# Cursor Local and Cloud Contract

Cursor protection has two local surfaces that sync into one Cloud app: **Cursor editor** and **Cursor CLI**. Local Guard must keep those surfaces distinct in detection, setup, repair, status, receipts, and Cloud sync while Cloud groups them under `/guard/apps/cursor`, `/guard/agents`, and `/guard/protect`.

## Surface ownership

| Surface | Local detection | Guard owns | Cursor owns |
| --- | --- | --- | --- |
| Cursor editor | Cursor app presence, user/workspace `.cursor/mcp.json`, Guard-managed editor setup marker | Trust checks, drift repair, redacted receipts, Cloud sync, unavailable-state explanation | Native editor approval and editor UI |
| Cursor CLI | `cursor-agent` availability, `cursor-agent mcp list`, Guard-managed CLI setup marker | CLI detection, repair handoff, status/test/remove receipts, Cloud freshness | Cursor CLI execution and native MCP behavior |

## Setup states

Each surface reports one setup state:

- `not_detected`: local Guard cannot find Cursor for this surface.
- `detected_unprotected`: Cursor exists locally, but Guard has not verified managed protection.
- `protected`: local Guard recently verified protection and synced a scoped receipt.
- `stale`: prior protection exists, but daemon or receipt freshness is outside policy.
- `unavailable`: the operating system, permissions, or installed Cursor build cannot support the surface.

## Repair states

Each surface reports one repair state:

- `ready`: Cloud can hand off a scoped repair intent to the local daemon.
- `requires_local_daemon`: the user must reconnect local Guard first.
- `requires_user_action`: the user must open Cursor, grant OS permission, or choose a workspace.
- `unsupported`: Guard explains the unsupported condition and must not offer a no-op repair.

## Sync and evidence fields

Cursor sync payloads include `surface`, `status`, `lastSeenAt`, `lastReceiptSyncedAt`, `daemonReachability`, and `protectedLocationId`. Cursor receipts include `receiptId`, `artifactId`, `actionScope`, `surface`, `redactedPath`, and `policyDecision`.

## Security boundaries

Activation tokens and daemon session tokens never render in Cloud UI or receipts. Local paths are redacted before Cloud sync unless the user explicitly exports a local proof bundle. Cloud repair intents are scoped to workspace, protected location, and Cursor surface. Cloud never invents Cursor activity; it shows real local receipts or an honest unavailable state.
