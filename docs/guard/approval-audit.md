# HOL Guard Approval Audit

## Scope

This note audits the current scanner-owned Guard approval flow in `ai-plugin-scanner`.

## What is working

- `hol-guard run <harness>` evaluates detected artifacts against stored Guard policy before launch.
- Interactive terminal sessions can approve or block directly from the inline Guard prompt.
- Non-interactive blocked runs queue approval requests in the local Guard daemon instead of failing with only a `diff` command.
- The local daemon persists pending approvals in SQLite and exposes:
  - request list and request detail
  - receipt list and receipt detail
  - latest artifact diff lookup
  - current policy decisions
  - policy upsert endpoints
- The local approval center serves a browser page on localhost with:
  - pending request list
  - per-request detail
  - changed fields
  - latest stored receipt evidence
  - scope selector and allow or block form

## What is fallback-only today

- Codex still uses the approval center rather than a richer in-client App Server approval surface.
- Gemini still relies on local approval center routing rather than a documented native approval UX.
- Terminal approval remains the only native path for direct in-session choices when Guard is launched from a normal interactive shell.

## What is still abrupt or confusing

- The local approval center is functional, but it is still a simple daemon-served HTML surface rather than a richer dedicated web app.
- Guard does not yet expose a first-class push/live-update channel from the daemon; clients currently poll HTTP endpoints.
- Some harnesses still rely on wrapper-level launch interruption rather than a fully native pause or resume model.

## Practical state by harness

- `claude-code`
  - strongest native policy surface
  - Guard can work with hooks plus fallback approval center
- `codex`
  - local approval center is the current approval UX
  - App Server remains the future richer path
- `cursor`
  - Guard focuses on artifact trust before native tool approval
- `antigravity`
  - Guard focuses on extension, MCP, and skill trust before editor launch
- `gemini`
  - Guard scans settings, hooks, extensions, skills, and MCP registrations, then routes blocked changes to the approval center
- `opencode`
  - Guard manages artifact trust while OpenCode keeps tool permission semantics

## Current recommendation

The current product center is now:

1. install Guard locally
2. run through Guard
3. approve in-context when possible
4. otherwise resolve from the local approval center
5. review receipts and diffs only when something changes

The next scanner-side UX upgrades should focus on:

- richer approval-center presentation
- live update transport
- cleaner pause or resume semantics for harnesses that cannot prompt inline

## Queue API contract

`GET /v1/requests` returns a paginated queue page:

```json
{
  "items": [
    {
      "request_id": "req_123",
      "harness": "codex",
      "artifact_id": "codex:project:tool",
      "artifact_name": "tool",
      "artifact_type": "mcp_server",
      "policy_action": "require-reapproval",
      "source_scope": "project",
      "config_path": "/workspace/.codex/config.toml",
      "workspace": "/workspace",
      "launch_target": "cat ~/.npmrc",
      "risk_summary": "Shell command can read a local secret file.",
      "risk_headline": "Secret file access",
      "action_identity": "{\"version\":\"v1\"}",
      "queue_group_id": "approval-group:v1:...",
      "dedupe_count": 1,
      "created_at": "2026-05-08T10:00:00+00:00",
      "last_seen_at": "2026-05-08T10:00:00+00:00",
      "display_status": "pending"
    }
  ],
  "next_cursor": null,
  "total_pending_count": 1,
  "total_count": 1,
  "status": "pending"
}
```

Supported query parameters:

- `status`: `pending`, `resolved`, or `all`
- `harness`: exact harness name
- `search`: command, prompt excerpt, MCP server/tool, path, or evidence text
- `cursor`: cursor returned by the previous page
- `limit`: page size, capped at 200

`POST /v1/requests/<request_id>/approve` and `POST /v1/requests/<request_id>/block` return a queue-aware resolution envelope:

```json
{
  "resolved": true,
  "item": {
    "request_id": "req_123",
    "status": "resolved",
    "resolution_action": "allow",
    "resolution_scope": "artifact"
  },
  "resolved_request": {
    "request_id": "req_123",
    "status": "resolved"
  },
  "remaining_pending_count": 2,
  "next_selectable_request_id": "req_456",
  "remaining_pending_summaries": [],
  "resolved_duplicate_ids": [],
  "resolution_summary": "Decision saved. 2 blocked actions remain.",
  "retry_hint": "Retry the action in your AI assistant if you approved it.",
  "copy": {
    "title": "Approved. Retry in chat.",
    "body": "Return to Codex and retry"
  }
}
```

`GET /v1/runtime` includes `queue_summary` with:

```json
{
  "active_request_id": "req_123",
  "next_request_id": "req_123",
  "remaining_pending_count": 3,
  "next_selectable_request_id": "req_123"
}
```
