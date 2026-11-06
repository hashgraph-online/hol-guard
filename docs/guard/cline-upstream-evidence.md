# Cline upstream integration evidence

Research lock: August 6, 2026.

| Surface | Pinned version | HOL Guard decision |
| --- | --- | --- |
| Cline VS Code | `4.1.6` | Native hooks are the release/3.0 default. Plugin mode requires an explicit live capability proof. |
| `@cline/cli` | `3.0.51` | AgentPlugin transport may be used after live before/after-tool proof. |
| `@cline/core` | `0.0.71` | AgentPlugin transport may be used after live before/after-tool proof. |
| Cline source tag commit | `81cce3d70e10244cdde40dbd0eb0bb711c93006d` | Source snapshot used to lock the adapter contract. |
| JetBrains | unverified | Detect only. Do not claim protection without a live blocking proof. |

## Hook surface observed

The researched Cline source exposes executable/file hook events including `PreToolUse`, `PostToolUse`, `UserPromptSubmit`, task lifecycle events, `PreCompact`, and `SessionShutdown`. Current Core payloads carry typed tool data under `tool_call.input` and `tool_result.output`; compatibility payloads use `preToolUse` and `postToolUse`.

Cline's native hook runner can continue after hook timeout, execution failure, or malformed output. HOL Guard therefore owns the fail-closed behavior at the managed `PreToolUse` bridge and returns a valid cancellation response when an action cannot be evaluated safely.

Native `PostToolUse` is asynchronous/observation-oriented and is not treated as a model-visible result replacement boundary.

## AgentPlugin surface observed

The researched Cline runtime includes an `AgentPlugin` hook model with `beforeTool` and `afterTool`. `beforeTool` can skip/stop an action. `afterTool` can return a replacement result. HOL Guard only reports plugin coverage as full after live evidence proves both a denied pre-tool call and a model-visible replaced/withheld post-tool result.

Public plugin documentation at the research lock described SDK/CLI/Kanban support and did not provide the same support guarantee for VS Code or JetBrains. Source presence inside the VS Code runtime is therefore treated as feature evidence, not as a public compatibility guarantee.

## MCP surface observed

Cline supports MCP configuration. HOL Guard uses this only as defense in depth: eligible local stdio servers can be routed through the existing Guard MCP proxy, while unsupported remote/OAuth entries are preserved. MCP proxying alone does not protect Cline's built-in shell, editor, file, browser, or patch tools.

## Locked product rules

- Use native hooks by default for Cline VS Code and unknown/mixed hosts.
- Use plugin mode only when the exact host passes the required live proof.
- Never leave managed native pre-tool enforcement and managed plugin enforcement active for the same Cline home once the selected transport is established.
- Do not read Cline `context_json_path` or `context_raw_path` temporary files in release/3.0.
- Do not treat a synthetic install canary as live Cline proof.
- JetBrains remains unverified until an exact live deny proof exists.

The machine-readable version lock is `tests/fixtures/cline/version-matrix.json`.
