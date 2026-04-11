# Guard Competitive Parity Matrix

## Scope

This matrix compares the current Guard phase against the SafeDep-style capability set from `guard-competitive-prd.md` and `guard-competitive-todo.md`.

Statuses:
- `shipped`
- `partial`
- `missing`
- `out-of-scope`

Roadmap labels:
- `parity`
- `advantage`
- `differentiator`
- `later`

## Capability Matrix

| Capability | Status | Why | Label |
| --- | --- | --- | --- |
| Local install-time protection | `partial` | `guard protect` now wraps install and registration commands for package and harness flows, but zero-config harness coverage is not complete across every ecosystem path. | `parity` |
| Runtime protection | `shipped` | Guard blocks before execution, persists receipts, carries incident context, and supports browser or terminal approval paths. | `parity` |
| Zero-config onboarding | `partial` | Stable daemon bootstrapping and direct CLI usage work immediately, but shell shim and guided minimal-config paths are still uneven by harness. | `parity` |
| Threat intelligence feed | `partial` | Broker verdict, advisory, revocation, and watchlist endpoints exist, but ingestion breadth and external curated feeds are still narrower than the PRD target. | `parity` |
| Inventory and discovery | `shipped` | Local inventory, synced inventory, inventory diff, and broker inventory endpoints are implemented. | `parity` |
| Exceptions management | `shipped` | Local and synced exceptions support owner, rationale, source, and expiry. | `parity` |
| ABOM export | `shipped` | Guard exports local ABOM and synced broker ABOM. | `parity` |
| Audit trail | `shipped` | Receipts, history, artifact timelines, receipt export, and local events now form a usable audit path. | `parity` |
| GitHub App / repo-side surface | `partial` | Scanner logic can power repo-side checks, but a coherent Guard GitHub App packaging and policy bridge is still incomplete. | `parity` |
| Centralized dashboard | `partial` | Portal and broker inventory, history, alerts, policy, and pricing surfaces exist, but frontend execution is still being refined separately. | `parity` |
| Org policy | `shipped` | Team policy packs, synced exceptions, and alert preferences are implemented in broker and portal support layers. | `parity` |
| Alerting | `partial` | Alert preferences, watchlist, and lifecycle events are implemented, but full outbound delivery breadth is still limited. | `parity` |
| Pricing and funnel | `partial` | Guard pricing, entitlements, and upgrade triggers exist, but premium packaging still needs broader product-surface enforcement. | `parity` |
| Harness-native trust | `shipped` | Guard classifies MCP servers, skills, plugin-like artifacts, commands, and harness config with harness-specific risk context. | `differentiator` |
| Consumer-to-maintainer loop | `partial` | Receipts, advisories, trust lookups, and attestation-aware verdicts exist, but maintainer-side remediation handoff is still incomplete. | `advantage` |
| Cross-harness trust memory | `shipped` | Guard policy, receipts, synced inventory, and team policy operate across Codex, Claude Code, Cursor, Gemini CLI, and OpenCode artifacts. | `differentiator` |
| Maintainer-side attestation bridge | `partial` | Trust resolution and registry-attested surfaces are wired in, but deeper maintainer remediation workflows remain incomplete. | `advantage` |
| OpenClaw remediation loop | `missing` | Consumer pain signals are not yet fully connected to maintainer-side remediation in `internet-dot`. | `later` |
| Hermes policy consumption | `missing` | Hermes consumption of Guard policy and receipts is not yet complete in this phase. | `later` |

## Summary

- `parity`: install-time protection packaging, threat feed depth, GitHub app packaging, dashboard polish, and alert delivery still need more work.
- `advantage`: consumer-to-maintainer trust loops and attestation bridges are real but not complete enough to market as finished.
- `differentiator`: harness-native trust and cross-harness trust memory are the strongest Guard advantages today.
- `later`: OpenClaw and Hermes integrations remain explicit later-phase work outside the repos completed here.
