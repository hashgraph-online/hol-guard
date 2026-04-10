# Guard Architecture

Guard lives inside `codex_plugin_scanner` and is the local product surface for harness protection. The existing scan engine remains the trust and evidence core, but the user workflow starts with local harness installs and launch interception rather than CI.

The runtime is split into:

- `guard/adapters`: harness discovery for Codex, Claude Code, Cursor, Gemini, and OpenCode
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

1. `guard start` detects supported harnesses and suggests the next step
2. `guard install <harness>` creates a local launcher shim
3. `guard run <harness>` evaluates changes before the harness launches
4. `guard receipts` and `guard status` let users inspect local decisions
5. `guard login` and `guard sync` stay optional

Wrapper mode is still the core execution strategy in this phase. Config mutation is limited to the Claude Code hook helper, where Guard can add and remove its own hook entry in workspace-local settings.
