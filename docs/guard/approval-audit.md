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
