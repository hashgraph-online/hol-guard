# All-Harness Hook Review Architecture

## Overview

HOL Guard's fast hook review engine is **harness-agnostic by design**. All
harnesses share the same daemon endpoint, review engine, and payload
normalization. All harnesses get the fast path for PostToolUse file reads.

## Shared Architecture (All Harnesses)

Every harness follows the same flow:

```
Harness Hook Script → /v1/hooks/{harness} → HookWorker → HookReviewEngine
                                                      ↓
                                            normalize_harness_payload()
                                            (handles codex, claude-code,
                                             pi, cursor, grok, zcode, etc.)
```

### What's Shared

- **Daemon route**: `/v1/hooks/{harness}` — generic, works for any harness
- **HookWorker**: `review_http_payload()` — harness-agnostic, uses `default_harness` from URL
- **HookReviewEngine**: `review()` → `_review_inner()` — uses `normalize_harness_payload()`
- **normalize_harness_payload()**: dispatches to per-harness normalizers
  (codex, claude-code, opencode, copilot, gemini, cursor, grok, pi, zcode)
- **ContentScanner**: same streaming secret scanner for all harnesses
- **HookDecisionCache**: same cache, keyed by content hash + stat + config
- **hook_output_text.extract_payload_output()**: extracts tool output text
  from any harness payload (checks `tool_response`, `stdout`, `output`, etc.)

### What's Harness-Specific

- **Hook script format**: Pi uses TypeScript, Claude Code uses JSON config,
  Codex uses TOML config, Cursor uses Python bridge
- **Client-side `guard_source_ref` generation**: Only Pi/OMP generates
  this in its TypeScript extension, enabling file-system caching with
  hash verification

## Fast Paths

All PostToolUse events go through the engine. The engine has two fast paths
depending on whether the harness provides `guard_source_ref`:

### Source-Ref Fast Path (Pi/OMP)

When a harness generates `guard_source_ref` client-side:
1. Hook script computes SHA256 of text-bearing output fields
2. Hook script sends `guard_source_ref` with the payload
3. Engine calls `evaluate_source_file_ref()`
4. Engine re-reads file, re-stats, re-hashes → exact match → `allow_original`
5. Results are cached by file stat + content hash
6. Model receives full reviewed content (no excerpt)

**Advantage**: File-system caching by stat identity — repeated reads of
the same file skip scanning entirely on cache hit.

### Server-Side Output Scanning (All Other Harnesses)

When a harness does NOT generate `guard_source_ref` (claude-code, codex,
grok, zcode, etc.):
1. Worker passes PostToolUse to the engine (no `HookWorkerUnsupported`)
2. Engine calls `_review_output_scan()`
3. `extract_payload_output()` extracts full tool output text from the payload
   (checks `tool_response`, `tool_output`, `stdout`, etc.)
4. `collect_output_text()` traverses the output value, extracting all
   text-bearing content — the same text the model would see
5. Full output is scanned by `ContentScanner` for secrets
6. If clean: `allow_original` (model sees full output)
7. If secrets found: `block` (model sees nothing)
8. If too large: `replace_with_reviewed_excerpt` (model sees safe excerpt)

**Security**: This is **more thorough** than the legacy CLI path because
it scans the complete output, not just a bounded excerpt. The scanner
sees exactly what the model would see.

**Gating**: Only `file_read` action types get the output scanning fast
path. Shell commands, MCP tools, and other action types still fall
through to `_review_standard` (which may block or return an excerpt).

### Legacy Path (Non-PostToolUse Events)

PreToolUse, UserPromptSubmit, and PermissionRequest events raise
`HookWorkerUnsupported`, causing the server to fall through to the
legacy CLI path. This preserves existing policy/permission/approval
checks for non-output events.

## Why Not Server-Side Source Ref Synthesis?

Server-side synthesis of `guard_source_ref` was considered but rejected
in favor of direct output scanning:

1. **Hash mismatch**: Harness output includes formatting (Claude Code's
   Read tool adds `     1\t` line numbers; Codex adds banners). The
   `output_equivalent()` check requires exact byte match between output
   text and file content.

2. **Vacuous hash check**: If the server synthesizes the hash from the
   file content, `output_equivalent()` compares the file hash against
   itself — always true. The hash check becomes meaningless.

3. **Output is already in the payload**: The daemon bridge forwards the
   full hook payload including tool output. Scanning the actual output
   is more secure than scanning the file on disk — it catches secrets
   in formatted output that might differ from the file.

## Testing

### Unit Tests

- `test_guard_hook_worker.py::TestHookWorkerAllHarnessFallback` — proves
  all harnesses (claude-code, codex, grok, zcode) get `allow_original`
  for safe PostToolUse file reads via server-side output scanning
- `test_guard_hook_worker.py::TestHookWorkerNonPostTool` — proves
  PreToolUse falls back to legacy for all harnesses
- `test_guard_hook_worker.py::TestHookWorkerReviewSafeSourceRef` — proves
  Pi's client-side `guard_source_ref` fast path still works

### Integration Tests

- `test_guard_surface_server.py::TestGuardDaemonFastHookPath` — exercises
  the full daemon HTTP path for Pi with `HOL_GUARD_HOOK_FAST_PATH=1`
- `tests/docker/test_all_harness_hooks.py` — Docker-based integration
  test that starts a real daemon and sends HTTP hook payloads for each
  harness, verifying fast-path behavior
