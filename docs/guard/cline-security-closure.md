# Cline security closure and rollback

This is the release/3.0 security closure record for the HOL Guard Cline adapter. Runtime status is evidence-based: installed files alone are never treated as proof that Cline is protected.

## Managed state and backup locations

Guard-owned state lives below `~/.hol-guard/managed/cline/` unless `HOL_GUARD_HOME` is configured elsewhere:

- `adapter-state.json` records the selected enforcement transport.
- `native-hooks-state.json` records native hook paths, worker paths, and integrity digests.
- `plugin-state.json` records the managed plugin path and integrity digest.
- `proofs/native-*.json` and `proofs/plugin-*.json` contain bounded proof metadata only.
- `hook-workers/` contains Guard-owned Python workers used by native Cline hooks.
- `mcp-backups/*.json` stores the exact original MCP settings text plus the original and Guard-managed hashes needed for conservative restoration.

Cline-facing Guard assets are written only to supported Guard-owned slots. The primary native hook root is `~/Documents/Cline/Hooks/`; the managed plugin root is `~/.cline/plugins/hol-guard/`. Guard refuses to overwrite user-owned files at managed slots.

## Runtime proof semantics

Synthetic installation canaries validate generated bridge syntax and wire behavior, but they do not count as live Cline security proof.

- Native `PreToolUse` is blocking-proven only after a fresh live Cline invocation records an actual `blocked` outcome. Allowed traffic does not make the transport ready.
- Native `PostToolUse` remains observation-only and never grants output-replacement coverage.
- Plugin pre-tool blocking requires a fresh live `blocked`/skip outcome.
- Plugin post-tool mediation requires a fresh live `replaced` outcome where `afterTool` returned a model-visible replacement or withheld result.
- Plugin `full`/ready status additionally requires a fresh plugin-load proof and current managed-file integrity.
- Missing, stale, or modified managed files degrade verification instead of being silently trusted.

## Security boundary matrix

| Boundary | Guard behavior | Closure expectation |
| --- | --- | --- |
| Shell and package commands | Current/compatibility Cline payloads normalize into Guard's shared action model; `run_commands` entries are evaluated independently. | A denied command cancels/skips before execution. Bridge failure on an action-bearing pre-tool event fails closed. |
| File reads/writes and patching | Typed tool input is normalized without reading Cline context temp files. | Contradictory security-relevant payload fields are rejected instead of guessed. |
| MCP stdio servers | Eligible local stdio servers are routed through the existing Guard MCP proxy. | Existing Guard MCP policy remains authoritative. |
| Remote/OAuth MCP | Remote entries are preserved rather than rewritten. | The coverage gap is reported and credentials are not copied into evidence. |
| Browser/network tools | URL-bearing tool input is normalized through shared Guard action fields. | Network policy receives the actual destination representation available from Cline. |
| Prompt/lifecycle hooks | Native hooks provide bounded local evidence. | Lifecycle failures do not become false enforcement proof. |
| Native tool output | Native `PostToolUse` is observation-only. | Guard does not claim model-visible output replacement. |
| Plugin tool output | `afterTool` may return a replacement or withheld error result. | Full coverage requires an actual live replacement proof. |
| Timeout/crash/malformed Guard response | Native/plugin pre-tool bridges deny or skip action-bearing work. | No silent allow on evaluation failure. |
| Managed-file tamper | Hook/plugin files and workers are integrity-bound. | Verification degrades and repair is recommended. |
| Duplicate enforcement transports | The adapter reconciles to one selected managed enforcement transport. | Duplicate managed transports are reported; one Cline call must not be reviewed twice. |
| User customization | Ownership checks and conservative restoration protect user files. | Modified/unowned files are retained rather than overwritten or deleted. |
| JetBrains | Detection is inventory only. | Remains unverified until an exact live pre-tool blocking proof exists. |

## Roll back plugin mode to native hooks

1. Run `hol-guard apps connect cline --surface hooks --json` (or `repair` with the same surface).
2. Guard installs and validates the native transport before cleaning up a healthy managed plugin. If the target cannot be validated, the transition is reported rather than treating the new transport as ready.
3. Run `hol-guard apps test cline --surface hooks --json`.
4. Native coverage remains `pre-execution`; native post-tool output is still observation-only.

## Disconnect and MCP restoration

Run `hol-guard apps disconnect cline --surface all` and then execute the exact confirmation command Guard returns. The confirmation command preserves the selected surface.

Guard removes only ownership-verified managed hooks, plugin files, and shims. For MCP settings, restoration is deliberately conservative:

1. The exact original text is saved before Guard rewrites an eligible settings file.
2. Guard records the hash of the managed version it wrote.
3. On disconnect, the original text is restored only if the current settings file still matches that managed hash.
4. If the user changed the file after Guard installation, Guard retains both the user's current file and the backup and reports that manual reconciliation is required.

This prevents disconnect or rollback from clobbering user edits.

## Release/3.0 limitations

- Cline VS Code defaults to native hooks.
- VS Code plugin mode is not treated as supported merely because plugin code exists in a Cline build; it requires explicit live capability proof.
- JetBrains remains detect-only/unverified without a live deny proof.
- Native `PostToolUse` cannot replace model-visible output.
- Synthetic package or CI smoke proves packaging and bridge construction, not a live IDE security boundary.
- Unsupported remote/OAuth MCP traffic remains outside local stdio proxy enforcement and must be shown as a blind spot.
