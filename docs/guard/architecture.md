# Guard Architecture

Guard lives inside `codex_plugin_scanner` and uses the existing scan engine as its trust and evidence core.

The runtime is split into:

- `guard/adapters`: harness discovery for Codex, Claude Code, Cursor, Gemini, and OpenCode
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

Wrapper mode is the default implementation strategy in this phase. Config mutation is limited to the Claude Code hook helper, where Guard can add and remove its own hook entry in workspace-local settings.
