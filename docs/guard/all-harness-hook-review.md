# All-Harness Hook Review Architecture

## Overview

HOL Guard's native hook boundary is **harness-agnostic by design**. All
harnesses share the same daemon endpoint, bounded raw-envelope transport, and
mechanical response projection. Supported hook decisions belong to Rust.

## Shared Architecture (All Harnesses)

Every harness follows the same flow:

```
Harness Hook Script → /v1/hooks/{harness} → HookWorker → Rust edge
                                                        ↓
                                              mechanical harness response
```

### What's Shared

- **Daemon route**: `/v1/hooks/{harness}` — generic, works for any harness
- **HookWorker**: `review_http_payload()` — launches native review and projects
  the already-decided result without semantic re-evaluation
- **Rust edge**: normalizes supported events, extracts bounded output, performs
  source I/O/scanning/policy decisions, and returns a typed result
- **Mechanical response projection**: renders native decisions for codex,
  claude-code, pi, cursor, grok, zcode, and other registered harnesses

### What's Harness-Specific

- **Hook script format**: Pi uses TypeScript, Claude Code uses JSON config,
  Codex uses TOML config, Cursor uses Python bridge
- **Client-side `guard_source_ref` generation**: Only Pi/OMP generates
  this in its TypeScript extension, enabling file-system caching with
  hash verification

## Fast Paths

All supported PostToolUse events go through the Rust edge. The edge preserves
the same two input shapes without delegating semantic ownership to Python:

### Source-Ref Fast Path (Pi/OMP)

When a harness generates `guard_source_ref` client-side:
1. Hook script computes SHA256 of text-bearing output fields
2. Hook script sends `guard_source_ref` with the payload
3. Rust validates the reference, securely re-reads/re-stats/re-hashes, and
   decides `allow_original` only on exact equivalence
4. Rust owns the source-read cache and decision
5. Model receives full reviewed content (no excerpt)

**Advantage**: File-system caching by stat identity — repeated reads of
the same file skip scanning entirely on cache hit.

### Server-Side Output Scanning (All Other Harnesses)

When a harness does NOT generate `guard_source_ref` (claude-code, codex,
grok, zcode, etc.):
1. Worker passes PostToolUse to the Rust edge (no Python semantic fallback)
2. Rust extracts full tool output text from the bounded payload
   (checks `tool_response`, `tool_output`, `stdout`, etc.)
3. Rust traverses the output value, extracting all
   text-bearing content — the same text the model would see
4. Full output is scanned by the Rust scanner for secrets
5. If clean: `allow_original` (model sees full output)
6. If secrets found: `block` (model sees nothing)
7. If too large: `replace_with_reviewed_excerpt` (model sees safe excerpt)

**Security**: This is **more thorough** than the legacy CLI path because
it scans the complete output, not just a bounded excerpt. The scanner
sees exactly what the model would see.

**Gating**: Rust classifies action types and applies the conservative floor.
Unknown, malformed, or unsupported input never selects a Python evaluator.

The Python reference evaluator, content scanner, and decision cache remain
available only to explicitly marked differential tests. Production `off` is a
fail-safe disablement; `shadow` comparison requires an explicit
non-production diagnostic surface.

## Rust Authority Boundary

Supported `PreToolUse` and `PostToolUse` semantic decisions are owned by the
version-matched bundled Rust runtime. Native unavailability, incompatibility,
overload, timeout, malformed output, or containment failure does not convert
into Python semantic evaluation. Those conditions fail closed.

Python remains outside the semantic authority boundary. It may authenticate and
transport a request, render the already-produced native result for a harness,
coordinate approval continuation, and persist bounded asynchronous evidence.
It may not parse or classify a supported `PreToolUse` command, lower a native
action floor, rescan supported `PostToolUse` output as an authoritative
fallback, or synthesize an allow after native failure.

The permanent ownership contract is recorded in
`docs/guard/contracts/hook-data-plane-ownership.v2.json` and enforced by
`.github/workflows/rust-authority-ownership.yml`.

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

- `test_python_hook_semantic_callgraph_gate.py` — proves production hook roots
  cannot reach the Python semantic evaluator and that `off` fails safe without
  an explicit oracle
- `tests/test_native_pretool_generic.py` — proves generic PreToolUse results
  stay typed and native across Claude, Codex, Cline, Cursor, Copilot, Grok, and
  ZCode; explicit off fail-safe is covered by
  `test_python_hook_semantic_callgraph_gate.py`
- native differential fixtures — compare Rust results with the explicit Python
  reference oracle without making Python authoritative
- `test_rust_pretool_authority.py` / `test_rust_posttool_authority.py` —
  prove `auto` and `force` fail closed when native is unavailable

### Integration Tests

- `test_guard_surface_server.py::TestGuardDaemonFastHookPath` — exercises
  the full daemon HTTP path for Pi with `HOL_GUARD_HOOK_FAST_PATH=1`
- `tests/docker/test_all_harness_hooks.py` — Docker-based integration
  test that starts a real daemon and sends HTTP hook payloads for each
  harness, verifying fast-path behavior
