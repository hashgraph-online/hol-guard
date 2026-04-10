# Guard Repo Boundaries

`ai-plugin-scanner` is the source of truth for the local Guard runtime.

This repo owns:

- harness adapters
- local CLI commands under `guard`
- local SQLite state
- receipts, diffs, and policy decisions
- wrapper-mode execution
- consumer-mode scan contracts

External repos stay optional in this phase:

- hosted Guard services: trust lookup, receipt sync, billing, and team policy when the user signs in
- `points-portal`: `/guard` onboarding, pricing, install docs, and signed-in dashboards
- `skill-publish`: HCS-26 provenance and attestation semantics
- sample Guard-compatible skills and MCP servers: first-party fixtures and canaries

Guard must still deliver local value when every online integration is unavailable.
