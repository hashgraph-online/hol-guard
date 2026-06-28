# All-Harness Hook Review Architecture

## Overview

HOL Guard's fast hook review engine is **harness-agnostic by design**. All
harnesses share the same daemon endpoint, review engine, and payload
normalization. The fast source-ref path is an optimization available to
harnesses that can generate `guard_source_ref` client-side.

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
- **Security**: same TOCTOU guard, sensitive-path check, symlink rejection, scanner

### What's Harness-Specific

- **Hook script format**: Pi uses TypeScript, Claude Code uses JSON config,
  Codex uses TOML config, Cursor uses Python bridge
- **Client-side `guard_source_ref` generation**: Only Pi/OMP currently
  generates this in its TypeScript extension

## Fast Path vs Legacy Path

### Fast Path (Pi/OMP only)

When a harness generates `guard_source_ref` client-side:
1. Hook script computes SHA256 of text-bearing output fields
2. Hook script sends `guard_source_ref` with the payload
3. Worker checks PostToolUse + has source_ref → runs engine
4. Engine re-reads file, re-stats, re-hashes → exact match → `allow_original`
5. Model receives full reviewed content (no excerpt)

**Why only Pi**: The fast path requires an exact hash match between the
output text the harness sends and the file content on disk. Pi's
`digestOutputText()` hashes the same structured output the server receives,
using the same text extraction logic as `collectOutputText()`. Other
harnesses format output differently (line numbers, banners, etc.), so
a client-side hash wouldn't match server-side file content.

### Legacy Path (All Other Harnesses)

When a harness doesn't generate `guard_source_ref`:
1. Worker raises `HookWorkerUnsupported` for PostToolUse without source_ref
2. Server catches this and falls through to legacy CLI
3. Legacy CLI runs full policy/permission/approval checks
4. For PostToolUse: output is reviewed via runtime artifact detection
5. If output is credential-looking: `require-reapproval` or `block`
6. If output is safe: `allow` (model sees full output)

**This is safe and correct.** The legacy path provides full security review.
The fast path is an optimization that avoids CLI startup cost for safe
source-file reads — it doesn't add security, it adds speed.

## Server-Side Synthesis (Considered, Rejected)

Server-side source ref synthesis was considered but rejected because:

1. **Hash mismatch**: Harness output includes formatting (Claude Code's
   Read tool adds `     1\t` line numbers; Codex adds banners). The
   `output_equivalent()` check requires exact byte match between output
   text and file content. `sha256("     1\tfile line") != sha256("file line")`.

2. **Security weakening**: Skipping the hash check for synthesized refs
   would weaken the security model — the server couldn't verify the
   payload text matches the file content, only that a file exists at
   the path.

3. **Per-harness output extraction**: Building per-harness extractors
   that strip formatting is fragile and harness-specific — the opposite
   of the abstracted pattern we want.

## Future: Enabling Fast Path for More Harnesses

To enable the fast path for claude-code, codex, or other harnesses:

1. **Add client-side `guard_source_ref` generation** to the harness hook
   script. This requires the hook script to:
   - Compute SHA256 of the output text using the same extraction logic
     as `collectOutputText()` (only text-bearing fields, not metadata)
   - Send `guard_source_ref` with `version`, `path`, `output_sha256`,
     `output_chars`, `tool_input_path`

2. **For TypeScript/JavaScript hooks** (like Pi): Embed a `digestOutputText()` function matching Pi's implementation

3. **For shell-based hooks** (Claude Code, Codex): The hook script would
   need to compute the hash in Python (the hook command already invokes
   Python). Add a `--synthesize-source-ref` flag to `guard hook` that
   computes the hash before sending the payload.

## Testing

### Unit Tests

- `test_guard_hook_worker.py::TestHookWorkerAllHarnessFallback` — proves
  all harnesses without `guard_source_ref` correctly raise
  `HookWorkerUnsupported` (fall back to legacy)
- `test_guard_hook_worker.py::TestHookWorkerNonPostTool` — proves
  PreToolUse falls back to legacy for all harnesses
- `test_hook_source_ref_snippet.py` — proves the shared TypeScript
  snippet has correct function signatures and security properties

### Integration Tests

- `test_guard_surface_server.py::TestGuardDaemonFastHookPath` — exercises
  the full daemon HTTP path for Pi with `HOL_GUARD_HOOK_FAST_PATH=1`
- `tests/docker/test_all_harness_hooks.py` — Docker-based integration
  test that starts a real daemon and sends HTTP hook payloads for each
  harness, verifying fast-path + legacy fallback behavior
