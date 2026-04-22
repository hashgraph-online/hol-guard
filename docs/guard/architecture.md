# Guard Architecture

Guard lives inside `codex_plugin_scanner` and is the local product surface for harness protection. The existing scan engine remains the trust and evidence core, but the user workflow starts with local harness installs and launch interception rather than CI.

The runtime is split into:

- `guard/adapters`: harness discovery for Codex, Claude Code, Copilot CLI, Cursor, Gemini, and OpenCode
- `guard/shims`: local launcher shims that route harness launches through Guard
- `guard/consumer`: orchestration for detection, policy evaluation, and consumer-mode scan output
- `guard/policy`: local action resolution for allow, review, warn, and block decisions
- `guard/receipts`: receipt creation for first use and changed-artifact events
- `guard/runtime`: wrapper-mode launch flow and optional sync endpoint integration
- `guard/store`: SQLite persistence for snapshots, diffs, receipts, managed installs, and sync state
- `guard/schemas`: stable JSON payloads for consumer-mode outputs

Guard evaluates local artifacts in this order:

1. Discover harness config and managed artifacts
2. Normalize each artifact into a stable snapshot
3. Compare against the last stored snapshot
4. Resolve the effective policy action
5. Record a receipt and optional diff
6. Launch the harness only if the effective action is not `block`

The local product loop is:

1. `hol-guard start` detects supported harnesses and suggests the next step
2. `hol-guard install <harness>` creates a local launcher shim
3. `hol-guard update` upgrades the installed Guard CLI in the current environment
4. `hol-guard run <harness>` evaluates changes before the harness launches
5. `hol-guard receipts` and `hol-guard status` let users inspect local decisions
6. `hol-guard connect` stays optional, with `hol-guard login` preserved as a compatibility alias

Wrapper mode is still the core execution strategy in this phase. Config mutation is limited to documented local hook helpers, where Guard can add and remove its own hook entries in workspace-local Claude settings or workspace-local Copilot CLI repo hooks.

For Microsoft Copilot, Guard supports two real local boundaries only:

1. the `copilot` CLI wrapper and repo-local `.github/hooks/*.json` hook surface
2. MCP artifact detection from `~/.copilot/mcp-config.json` and workspace `.vscode/mcp.json`

That does not extend to VS Code Copilot extension-host interception.

Cisco AIBOM stays out of Guard runtime policy in this phase. If it returns later, it should attach to evidence or export paths rather than launch blocking or approval flow.
